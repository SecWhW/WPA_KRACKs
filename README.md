# RSS-KRACK Attacks: Formal Verification and Experimental Validation

This repository combines **formal verification** of WPA2/3 KRACK attacks using the Tamarin Prover with an **experimental reproduction** of the WNM-based KRACK attack and an evaluation of the RSS-KRACK defense for WPA2/3.

The project provides two complementary forms of evidence:

1. **Formal models** that describe KRACK attack variants, GTK reinstallation behavior, WNM-based attacks, and corresponding defenses.
2. **Experimental validation** that reproduces the WNM KRACK attack in a virtual wireless environment, confirms `ReinstallGTK` from victim-side `wpa_supplicant` logs, and verifies that the RSS-KRACK patch prevents reinstallation without breaking normal WPA2/WPA3 operations.

---

## 1. Formal Verification with Tamarin

### 1.1 Prerequisites

The formal models were produced using the latest extended Tamarin Prover used by this project, version **1.7.1**.

#### Install Tamarin

Installation instructions:

https://tamarin-prover.github.io/manual/book/002_installation.html

#### Docker Image

A pre-built Tamarin version supporting natural numbers is available from Cremers et al.

Pull the Docker image:

```bash
docker pull securityprotocolsresearch/tamarin:st
```

Run the container:

```bash
docker run -it securityprotocolsresearch/tamarin:st bash
```

You can copy the extended Tamarin binary from the image and use it to run the models.

#### Launch Interactive GUI

For example, run the latest defense model:

```bash
./subterm-tamarin interactive WPA_WNM_new_attack_Fix.spthy
```

Then open:

```text
http://127.0.0.1:3001
```

to inspect proofs, attack traces, and protocol states interactively.

---

### 1.2 Formal Model Repository Structure

| File | Description | Attack type |
|------|-------------|-------------|
| `WPA_plaintext_handshake_init.spthy` | plaintext handshake model with KRACK attack. | IV Reuse to leak key |
| `WPA_plaintext_handshake_race_condition.spthy` | Plaintext handshake model allowing two consecutive key installation commands. | IV Reuse to leak key |
| `WPA_plaintext_handshake_race_condition_newdefinition.spthy` | Alternative attack definition to avoid Tamarin looping on unknown ciphertext sources. | IV Reuse to leak key |
| `WPA_ciphertext_handshake_init.spthy` | ciphertext handshake model with KRACK attack. | IV Reuse to leak key |
| `WPA_ciphertext_handshake_race_condition.spthy` | Ciphertext handshake model allowing two consecutive key installation commands. | IV Reuse to leak key |
| `WPA_GTK_Init_Attack.spthy` | GTK handshake KRACK attack model. | Multicast Reuse to replay command |
| `WPA_GTK_Rekeys.spthy` | GTK rekeying model implementing the official two-key mitigation. | Multicast Reuse to replay command |
| `WPA_WNM_init_attack.spthy` | WNM-based attack bypassing earlier GTK protections. | Multicast Reuse to replay command |
| `WPA_WNM_new_attack.spthy` | WNM-based attack bypassing the latest four-key protection. | Multicast Reuse to replay command |
| `WPA_WNM_new_attack_Fix.spthy` | Defense model where the client randomizes all four keys. | Multicast Reuse to replay command |

#### Additional Formal Verification Resources

- `Proof/` contains proof scripts and verification results for all models.
- `attack_pic/` contains attack traces and graphical illustrations of the attacks.

---

## 2. WNM KRACK Experimental Validation

**Experimental Environment**: Windows host → VMware → Ubuntu 24.04 VM (`mac80211_hwsim` virtual wireless)  
**Corresponding Paper**: RSS-KRACK (WPA2/3)

### 2.1 Objective

The experiment verifies the WNM (Wireless Network Management)-based KRACK attack described in the paper and evaluates the effectiveness of the RSS-KRACK defense.

The core goal is to directly prove **ReinstallGTK** at the victim `wpa_supplicant` memory/key-state level: the same GTK is installed twice, and during the second installation the RSC (Receive Sequence Counter) is reset to 0.

This experimental stage complements the formal models by showing the same security-relevant behavior in an executable wireless test environment.

---

### 2.2 Attack Principle

In WPA2/3, the GTK (Group Temporal Key) is distributed via the Group Key Handshake. To prevent replay attacks, `wpa_supplicant` maintains a 4-key window (`gtk1/gtk2/wnm1/wnm2`). A new GTK is installed only if it does not exist in these four slots.

The attack exploits a boundary condition: by advancing the four key slots, `GTK_0` is evicted from the window. Replaying an old Group Key Msg1 containing `GTK_0` then causes the four-key check to pass and triggers `GTK_0` reinstallation (`ReinstallGTK`).

#### Attack Steps

| Step | Operation | Description |
|------|-----------|-------------|
| Step 1 | AP sends broadcast frame | Encrypted with `GTK_0`, PN = `z+1` |
| Step 2 | Attacker saves `GTK_0` | Retrieved via hostapd control interface |
| Step 3 | Advance 4 key slots | `RENEW_GTK ×2 + RESEND_GROUP_M1 maxrsc ×2` |
| Step 4 | Replay old `GTK_0` Msg1 | Triggers **ReinstallGTK** |
| Step 5 | Replay old broadcast frame | Decrypted using reinstalled `GTK_0` |

#### Key Conditions for Success

- `GTK_0` is evicted from the 4-key window.
- RSC is reset to 0 upon reinstall.
- Old PN-based replay protection is broken.
- The same (`GTK_0`, `PN=z+1`) ciphertext appears twice, enabling plaintext recovery.

---

## 3. Experimental Setup

### 3.1 Virtual Wireless Topology

```text
mac80211_hwsim virtual wireless environment (Ubuntu 24.04 VM)
├── wlan0  → modified hostapd v2.7-devel (AP role)
│             MAC: 02:00:00:00:00:00
├── wlan1  → wpa_supplicant (victim)
│             MAC: 02:00:00:00:01:00
│             Attack mode: system version v2.10 (/usr/sbin/wpa_supplicant)
│             Defense mode: RSS-KRACK patched v2.7-devel
└── hwsim0 → monitoring + packet capture interface
```

### 3.2 Software Versions

| Component | Version | Description |
|----------|---------|-------------|
| hostapd | v2.7-devel (modified) | Added `GET_GTK` and `SEND_GROUP_M1_WITH_GTK` |
| wpa_supplicant (attack) | v2.10 (system) | Unpatched KRACK version |
| wpa_supplicant (defense) | v2.10(RSS-KRACK patch) | Algorithm 1 GTK branch implemented |
| Python | 3.x + Scapy 2.6.1 | Attack script |
| mac80211_hwsim | Linux kernel module | Virtual wireless interface |

### 3.3 Network Configuration

```text
SSID: testnetwork
PSK:  abcdefgh
Encryption: WPA2-Personal / AES-CCMP
```

---

## 4. Experimental Implementation

### 4.1 hostapd Modifications

Two control-interface commands were added in `hostapd/ctrl_iface.c`.

#### `GET_GTK`

Returns the current GTK in hexadecimal format.

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

#### `SEND_GROUP_M1_WITH_GTK <mac> <gtk_hex>`

Replays Group Key Msg1 using a specified GTK value.

### 4.2 CCMP Encrypted Broadcast Frame

```python
def encrypt_broadcast_frame(gtk_hex, pn, ap_mac, bcast_mac, keyid=1):
    gtk = bytes.fromhex(gtk_hex)
    plaintext_frame = build_broadcast_arp_plaintext(ap_mac, bcast_mac)
    encrypted = encrypt_ccmp(plaintext_frame, gtk, pn, keyid=keyid)
    return encrypted
```

Frame format:

```text
Dot11 (from-DS, broadcast) / LLC+SNAP / ARP
```

### 4.3 ReinstallGTK Evidence Collection

Run `wpa_supplicant` with detailed key logging:

```bash
wpa_supplicant -i wlan1 -c /tmp/victim.conf -D nl80211 -d -K 2>&1 | tee /tmp/wpa_debug_fig6.log
```

Relevant log patterns:

```text
WPA: Group Key - hexdump(len=16): xx xx xx ...
WPA: Installing GTK to the driver (keyidx=1)
```

If the same GTK appears twice, `ReinstallGTK` is confirmed.

---

## 5. Experimental Results

### 5.1 Attack Mode — wpa_supplicant Unpatched v2.10

**Result**: `REINSTALL_CONFIRMED`

| # | Line | keyidx | GTK | Description |
|---|------|--------|-----|-------------|
| 1 | 652 | 1 | `061be929883b148b5de7a07d8dc304a6` | Initial install |
| 2 | 727 | 1 | `10e3da54d30a7644c0680a45598f7df3` | After renewal |
| 3 | 840 | 1 | `061be929883b148b5de7a07d8dc304a6` | ReinstallGTK |

> Note: The second log entry corresponds to four GTK key installations(see attack.py for more details), so the three displayed security-critical log entries represent six GTK installations in total.

### 5.2 Defense Mode — wpa_supplicant RSS-KRACK v2.10 Patched

**Result**: `DEFENDED`

| # | Line | keyidx | GTK | Description |
|---|------|--------|-----|-------------|
| 1 | 272 | 1 | `bd5ce7b960c4ce5ff0d06861c64f1bf4` | Single install |

> Note: Only the initial installation is accepted.

### 5.3 Attack vs Defense Comparison

| Metric | Attack Mode | Defense Mode |
|--------|-------------|--------------|
| GTK installs | 3 displayed security-critical entries | 1 |
| ReinstallGTK | Yes | No |
| RSC reset | Yes | No |
| PN reuse | Possible | Prevented |
| Result | `REINSTALL_CONFIRMED` | `DEFENDED` |

---

## 6. RSS-KRACK Defense Mechanism

### 6.1 Algorithm

```text
if handshake == GTK:
    GTK = [Randomize(), Randomize(), Randomize(), Randomize()]
```

### 6.2 Behavior

1. Detect repeated GTK in the four-slot window.
2. Randomize all GTK slots.
3. Reject reinstallation.

The corresponding formal defense model is:

```text
WPA_WNM_new_attack_Fix.spthy
```

which models the client randomizing all four keys.

---

## 7. Normal Operation Verification

### 7.1 Purpose

The RSS-KRACK defense patch modifies the key-installation logic in `wpa_supplicant_install_ptk()` and `wpa_supplicant_install_gtk()`. It is therefore necessary to verify that the patch does not break normal WPA2/WPA3 protocol operations.

The patched `wpa_supplicant` is tested for:

1. **4-way handshake** for WPA2-PSK and WPA3-SAE.
2. **GTK rekeying** via the Group Key Handshake.
3. **WNM sleep mode** GTK distribution.

### 7.2 Test Script

**Location**: `scripts/test_patched_normal_operation.sh`

```bash
chmod +x scripts/test_patched_normal_operation.sh
sudo scripts/test_patched_normal_operation.sh
```

### 7.3 Test 1 — WPA2-PSK 4-way Handshake

Configuration:

```text
key_mgmt=WPA-PSK
proto=RSN
pairwise=CCMP
group=CCMP
```

Verification criteria:

- 4-way handshake completes successfully.
- PTK is installed exactly once, with no reinstallation.
- GTK is installed exactly once.
- EAPOL frames (Msg1–Msg4) are captured in pcap.

Expected log output:

```text
WPA: Key negotiation completed with 02:00:00:00:00:00
WPA: Installing PTK to the driver (keyidx=0)
WPA: Installing GTK to the driver (keyidx=1)
```

### 7.4 Test 2 — WPA3-SAE 4-way Handshake

Configuration:

```text
key_mgmt=SAE
sae_password="abcdefgh"
ieee80211w=2
```

WPA3-SAE requires:

- Linux kernel ≥ 5.2 (SAE support in nl80211).
- hostapd with SAE enabled.

Verification criteria:

- SAE authentication is initiated.
- Negotiation completes with `key_mgmt=SAE`.
- PMF (`ieee80211w=2`) protection is active.
- Connection is established through the WPA3 path.

Confirm WPA3 in the log using:

```text
RSN: using key_mgmt SAE
SAE: Authentication commit/confirm
WPA: Key negotiation completed
```

A WPA2 fallback instead shows:

```text
RSN: using key_mgmt WPA-PSK
```

For true WPA3 verification, use:

- hostapd: `wpa_key_mgmt=SAE`
- wpa_supplicant: `key_mgmt=SAE`

### 7.5 Test 3 — GTK Rekeying

Configuration:

```text
wpa_group_rekey=10   # hostapd: renew GTK every 10 seconds
```

Verification criteria:

- Multiple GTK installations occur through normal rekeying.
- Every GTK value is unique.
- Group Key Msg1/Msg2 handshake completes.
- No connection interruption occurs during rekey.

Expected behavior in a 30-second window:

- Initial connection: `GTK_0` installed.
- 10s: `GTK_1` installed.
- 20s: `GTK_2` installed.

All three GTK values should be different. If a GTK repeats, the RSS-KRACK defense should detect and reject it.

Embedded Python verification:

```python
gtk_values = extract_gtk_from_log(log_file)
unique_gtks = set(gtk_values)

if len(gtk_values) == len(unique_gtks):
    print("[PASS] All GTK values are unique (no reinstallation)")
else:
    print("[FAIL] GTK reinstallation detected")
```

### 7.6 Test 4 — WNM Sleep Mode GTK Handling

Trigger:

```bash
hostapd_cli -i wlan0 resend_group_m1 <client_mac> maxrsc
```

Purpose: verify that the patched client correctly handles GTK distribution via WNM sleep mode, which is the attack vector used by the WNM KRACK experiment.

Verification criteria:

- WNM GTK message is processed without a crash.
- No segmentation faults or unexpected termination occur.
- GTK handling follows the RSS-KRACK defense logic.

---

## 8. WPA2 vs WPA3 Support

The same `wpa_supplicant 2.10` binary supports both WPA2 and WPA3. The protocol actually used depends on runtime negotiation.

| Configuration | AP Capability | Result |
|---------------|---------------|--------|
| `key_mgmt=WPA-PSK` | WPA2-PSK | **WPA2-PSK** |
| `key_mgmt=SAE` | WPA3-SAE | **WPA3-SAE** |
| `key_mgmt=SAE WPA-PSK` | WPA3-SAE | **WPA3-SAE** (preferred) |
| `key_mgmt=SAE WPA-PSK` | WPA2-PSK only | **WPA2-PSK** (fallback) |

Confirm WPA3:

```text
RSN: using key_mgmt SAE
SAE: Authentication commit
SAE: Authentication confirm
WPA: Key negotiation completed
```

WPA2 fallback:

```text
RSN: using key_mgmt WPA-PSK
WPA: RX message 1 of 4-Way Handshake from 02:00:00:00:00:00
```

Key authentication difference:

- WPA2 uses a pre-shared key (PSK).
- WPA3 uses Simultaneous Authentication of Equals (SAE).

---

## 9. Expected Normal-Operation Results

| Test | Pass Criteria |
|------|---------------|
| WPA2 4-way | PTK + GTK installed once each; connection successful |
| WPA3 4-way | SAE authentication completes; `key_mgmt=SAE` confirmed in log |
| GTK rekey | Multiple GTK installations; all values unique |
| WNM mode | No crashes; GTK handled correctly |

Expected success summary:

```text
[SUCCESS] All tests passed!
[RESULT] RSS-KRACK patched wpa_supplicant handles normal operations correctly:
  ✓ WPA2-PSK 4-way handshake
  ✓ WPA3-SAE 4-way handshake (if supported)
  ✓ GTK rekeying (Group Key handshake)
  ✓ WNM sleep mode GTK handling
```

This normal-operation verification is used to show that the RSS-KRACK defense patch prevents key reinstallation attacks while preserving expected protocol behavior in the tested WPA2/WPA3 scenarios.

---

## 10. Experiment Files and Generated Evidence

### Attack / Defense Experiment Files

| File | Description |
|------|-------------|
| `scripts/attack.py` | Full attack implementation |
| `hostapd/ctrl_iface.c` | Modified hostapd |
| `hostapd/ctrl_iface.diff` | Patch diff |
| `captures/*.pcapng` | Packet captures |
| `logs/*.log` | Result logs |
| `wpa_debug_*.log` | Raw WPA debug logs |

### Normal Operation Evidence

| File | Description |
|------|-------------|
| `logs/normal_operation/wpa_supplicant_wpa2_*.log` | WPA2-PSK connection log |
| `logs/normal_operation/wpa_supplicant_wpa3_*.log` | WPA3-SAE connection log |
| `logs/normal_operation/wpa_supplicant_gtk_*.log` | GTK rekeying test log |
| `logs/normal_operation/wpa_supplicant_wnm_*.log` | WNM handling test log |
| `captures/normal_operation/*.pcapng` | Packet captures for each test |

---

## 11. Overall Conclusion

The combined formal and experimental workflow provides a complete verification chain for the WNM-based KRACK scenario covered by this project:

1. The Tamarin models formally represent WPA/KRACK attack variants, including WNM-based attacks that bypass earlier GTK protections.
2. `WPA_WNM_new_attack.spthy` models the WNM attack against the four-key protection, while `WPA_WNM_new_attack_Fix.spthy` models the defense in which the client randomizes all four keys.
3. The virtual `mac80211_hwsim` experiment reproduces the WNM-based attack and confirms victim-side `ReinstallGTK` behavior.
4. The attack-mode logs show the same GTK being installed again, together with RSC reset behavior and possible PN reuse.
5. The RSS-KRACK defense prevents GTK reinstallation in the defense experiment.
6. Additional WPA2, WPA3, GTK rekeying, and WNM handling tests verify normal operation of the patched client in the scenarios covered by the test suite.

Together, the formal models, proof artifacts, attack traces, packet captures, and victim-side logs provide complementary evidence for both the attack and the RSS-KRACK mitigation.
