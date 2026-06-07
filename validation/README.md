# WNM KRACK New Attack Detection

**Experimental Environment**: Windows host → VMware → Ubuntu 24.04 VM (mac80211_hwsim virtual wireless)  
**Corresponding Paper**: RSS-KRACK (WPA2_CN), Figure 6 "A New KRACK Attack Using WNM"

---

## I. Objective

This experiment verifies the WNM (Wireless Network Management)-based KRACK attack described in the paper and evaluates the effectiveness of the RSS-KRACK defense.

The core goal is to directly prove **ReinstallGTK** at the victim wpa_supplicant memory/key state level — i.e., the same GTK is installed twice, and during the second installation the RSC (Receive Sequence Counter) is reset to 0.

---

## II. Attack Principle

### 2.1 Background

In WPA2/3, the GTK (Group Temporal Key) is distributed via the Group Key Handshake. To prevent replay attacks, wpa_supplicant maintains a 4-key window (gtk1/gtk2/wnm1/wnm2). A new GTK is installed only if it does not exist in these four slots.

The attack exploits a boundary condition: by advancing the 4 key slots, GTK_0 is evicted from the window. Then, replaying an old Group Key Msg1 containing GTK_0 causes the 4-key check to pass and triggers GTK_0 reinstallation (ReinstallGTK).

---

### 2.2 Attack Steps

| Step | Operation | Description |
|------|----------|-------------|
| Step 1 | AP sends broadcast frame | Encrypted with GTK_0, PN = z+1 |
| Step 2 | Attacker saves GTK_0 | Retrieved via hostapd control interface |
| Step 3 | Advance 4 key slots | RENEW_GTK ×2 + RESEND_GROUP_M1 maxrsc ×2 |
| Step 4 | Replay old GTK_0 Msg1 | Triggers **ReinstallGTK** |
| Step 5 | Replay old broadcast frame | Decrypted using reinstalled GTK_0 |

---

### 2.3 Key Conditions for Success

- GTK_0 is evicted from 4-key window
- RSC is reset to 0 upon reinstall
- Old PN-based replay protection is broken
- Same (GTK_0, PN=z+1) ciphertext appears twice → enables plaintext recovery

---

## III. Experimental Setup

### 3.1 Virtual Wireless Topology

```
mac80211_hwsim virtual wireless environment (Ubuntu 24.04 VM)
├── wlan0  → modified hostapd v2.7-devel (AP role)
│             MAC: 02:00:00:00:00:00
├── wlan1  → wpa_supplicant (victim)
│             MAC: 02:00:00:00:01:00
│             Attack mode: system version v2.10 (/usr/sbin/wpa_supplicant)
│             Defense mode: RSS-KRACK patched v2.7-devel
└── hwsim0 → monitoring + packet capture interface
```

---

### 3.2 Software Versions

| Component | Version | Description |
|----------|--------|-------------|
| hostapd | v2.7-devel (modified) | Added GET_GTK and SEND_GROUP_M1_WITH_GTK |
| wpa_supplicant (attack) | v2.10 (system) | Unpatched KRACK version |
| wpa_supplicant (defense) | v2.7-devel (RSS-KRACK patch) | Algorithm 1 GTK branch implemented |
| Python | 3.x + Scapy 2.6.1 | Attack script |
| mac80211_hwsim | Linux kernel module | Virtual wireless interface |

---

### 3.3 Network Configuration

```
SSID: testnetwork
PSK:  abcdefgh
Encryption: WPA2-Personal / AES-CCMP
```

---

## IV. Implementation

### 4.1 hostapd Modifications

Two control interface commands were added in `hostapd/ctrl_iface.c`.

#### GET_GTK

Returns current GTK in hex format.

```c
static int hostapd_get_gtk(struct hostapd_data *hapd, char *buf, size_t buflen)
{
    struct wpa_group *gsm;
    int res;
    if (!hapd->wpa_auth || !hapd->wpa_auth->group)
        return -1;

    gsm = hapd->wpa_auth->group;
    res = wpa_snprintf_hex(buf, buflen, gsm->GTK[gsm->GN - 1], gsm->GTK_len);

    buf[res++] = '\n';
    buf[res] = '\0';
    return res;
}
```

#### SEND_GROUP_M1_WITH_GTK <mac> <gtk_hex>

Replays Group Key Msg1 using a specified GTK value.

---

### 4.2 CCMP Encrypted Broadcast Frame

```python
def encrypt_broadcast_frame(gtk_hex, pn, ap_mac, bcast_mac, keyid=1):
    gtk = bytes.fromhex(gtk_hex)
    plaintext_frame = build_broadcast_arp_plaintext(ap_mac, bcast_mac)
    encrypted = encrypt_ccmp(plaintext_frame, gtk, pn, keyid=keyid)
    return encrypted
```

Frame format:

```
Dot11 (from-DS, broadcast) / LLC+SNAP / ARP
```

---

### 4.3 ReinstallGTK Evidence Collection

wpa_supplicant is run with:

```bash
wpa_supplicant -i wlan1 -c /tmp/victim.conf -D nl80211 -d -K 2>&1 | tee /tmp/wpa_debug_fig6.log
```

Log patterns:

```
WPA: Group Key - hexdump(len=16): xx xx xx ...
WPA: Installing GTK to the driver (keyidx=1)
```

If the same GTK appears twice → ReinstallGTK confirmed.

---

## V. Experimental Results

### 5.1 Attack Mode (Unpatched v2.10)

**Timestamp**: 2026-05-28 00:54:52  
**Result**: REINSTALL_CONFIRMED

| # | Line | keyidx | GTK | Description |
|--|------|--------|-----|-------------|
| 1 | 652 | 1 | 061be929883b148b5de7a07d8dc304a6 | Initial install |
| 2 | 727 | 1 | 10e3da54d30a7644c0680a45598f7df3 | After renewal |
| 3 | 840 | 1 | 061be929883b148b5de7a07d8dc304a6 | ReinstallGTK |

---

### 5.2 Defense Mode (RSS-KRACK v2.7-devel)

**Timestamp**: 2026-05-28 00:56:41  
**Result**: DEFENDED

| # | Line | keyidx | GTK | Description |
|--|------|--------|-----|-------------|
| 1 | 272 | 1 | bd5ce7b960c4ce5ff0d06861c64f1bf4 | Single install |

---

### 5.3 Comparison

| Metric | Attack Mode | Defense Mode |
|--------|------------|--------------|
| GTK installs | 3 | 1 |
| ReinstallGTK | Yes | No |
| RSC reset | Yes | No |
| PN reuse | Possible | Prevented |
| Result | REINSTALL_CONFIRMED | DEFENDED |

---

## VI. RSS-KRACK Defense Mechanism

### Algorithm

```
if handshake == GTK:
    GTK = [Randomize(), Randomize(), Randomize(), Randomize()]
```

### Behavior

1. Detect repeated GTK in 4-slot window
2. Randomize all GTK slots
3. Reject reinstallation

---

## VII. Experiment Files

| File | Description |
|------|-------------|
| scripts/attack.py | Full attack implementation |
| hostapd/ctrl_iface.c | Modified hostapd |
| hostapd/ctrl_iface_fig6.diff | Patch diff |
| captures/*.pcapng | Packet captures |
| logs/*.log | Result logs |
| wpa_debug_*.log | Raw WPA debug logs |

---

## VIII. Conclusion

This experiment reproduces the WNM-based KRACK attack in a mac80211_hwsim virtual wireless environment.

1. Attack successfully triggers ReinstallGTK.
2. Same GTK is installed twice, resetting RSC to 0.
3. RSS-KRACK prevents reinstallation via slot randomization.
4. Evidence is confirmed from victim-side wpa_supplicant logs.
