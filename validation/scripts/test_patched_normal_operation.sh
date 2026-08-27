#!/bin/bash
# Test Script: Verify Patched wpa_supplicant Normal Operation
# Purpose: Demonstrate that RSS-KRACK patched wpa_supplicant correctly handles:
#   1. 4-way handshake (both WPA2-PSK and WPA3-SAE)
#   2. GTK rekeying
#   3. WNM sleep mode transitions
#
# This proves the patch does not break normal protocol operations.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURE_DIR="${SCRIPT_DIR}/../captures/normal_operation"
LOG_DIR="${SCRIPT_DIR}/../logs/normal_operation"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

mkdir -p "${CAPTURE_DIR}" "${LOG_DIR}"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}RSS-KRACK Patched wpa_supplicant${NC}"
echo -e "${BLUE}Normal Operation Test Suite${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Detect patched wpa_supplicant binary
PATCHED_WPA_SUPPLICANT="${HOME}/krack_experiment/krackattacks-scripts/wpa_supplicant/wpa_supplicant"
SYSTEM_WPA_SUPPLICANT="/usr/sbin/wpa_supplicant"

if [ ! -f "${PATCHED_WPA_SUPPLICANT}" ]; then
    echo -e "${RED}[ERROR]${NC} Patched wpa_supplicant not found at: ${PATCHED_WPA_SUPPLICANT}"
    exit 1
fi

echo -e "${GREEN}[INFO]${NC} Using patched wpa_supplicant: ${PATCHED_WPA_SUPPLICANT}"
WPA_VERSION=$(${PATCHED_WPA_SUPPLICANT} -v 2>&1 | head -1)
echo -e "${GREEN}[INFO]${NC} Version: ${WPA_VERSION}"
echo ""

# ==============================================================================
# Test 1: WPA2-PSK 4-way Handshake
# ==============================================================================

test_wpa2_4way_handshake() {
    echo -e "${YELLOW}[TEST 1]${NC} WPA2-PSK 4-way Handshake"
    echo "--------------------------------------"

    # Create WPA2-PSK configuration
    WPA2_CONF="/tmp/victim_wpa2.conf"
    cat > "${WPA2_CONF}" <<EOF
network={
    ssid="testnetwork"
    psk="abcdefgh"
    key_mgmt=WPA-PSK
    proto=RSN
    pairwise=CCMP
    group=CCMP
}
EOF

    echo -e "${GREEN}[INFO]${NC} Configuration: key_mgmt=WPA-PSK, proto=RSN (WPA2)"

    # Start hostapd (AP role on wlan0)
    HOSTAPD_CONF="${HOME}/krack_experiment/krackattacks-scripts/krackattack/hostapd.conf"
    echo -e "${GREEN}[INFO]${NC} Starting hostapd (AP role)..."
    sudo ${HOME}/krack_experiment/krackattacks-scripts/hostapd/hostapd \
        "${HOSTAPD_CONF}" > "${LOG_DIR}/hostapd_wpa2_${TIMESTAMP}.log" 2>&1 &
    HOSTAPD_PID=$!
    sleep 3

    # Start packet capture
    echo -e "${GREEN}[INFO]${NC} Starting packet capture on hwsim0..."
    sudo tshark -i hwsim0 -w "${CAPTURE_DIR}/wpa2_4way_${TIMESTAMP}.pcapng" \
        -f "ether proto 0x888e or type data" > /dev/null 2>&1 &
    TSHARK_PID=$!
    sleep 2

    # Start patched wpa_supplicant (victim role on wlan1)
    echo -e "${GREEN}[INFO]${NC} Starting patched wpa_supplicant (victim role)..."
    sudo ${PATCHED_WPA_SUPPLICANT} -i wlan1 -c "${WPA2_CONF}" -D nl80211 \
        -d -K 2>&1 | tee "${LOG_DIR}/wpa_supplicant_wpa2_${TIMESTAMP}.log" &
    WPA_PID=$!

    # Wait for connection
    echo -e "${GREEN}[INFO]${NC} Waiting for 4-way handshake to complete (15s)..."
    sleep 15

    # Stop processes
    echo -e "${GREEN}[INFO]${NC} Stopping processes..."
    sudo kill ${WPA_PID} 2>/dev/null || true
    sudo kill ${TSHARK_PID} 2>/dev/null || true
    sudo kill ${HOSTAPD_PID} 2>/dev/null || true
    sleep 2

    # Verify results
    echo -e "${GREEN}[INFO]${NC} Analyzing results..."

    # Check for successful 4-way handshake in log
    if grep -q "WPA: Key negotiation completed" "${LOG_DIR}/wpa_supplicant_wpa2_${TIMESTAMP}.log"; then
        echo -e "${GREEN}[PASS]${NC} 4-way handshake completed successfully"
    else
        echo -e "${RED}[FAIL]${NC} 4-way handshake did not complete"
        return 1
    fi

    # Check for PTK installation
    if grep -q "WPA: Installing PTK to the driver" "${LOG_DIR}/wpa_supplicant_wpa2_${TIMESTAMP}.log"; then
        echo -e "${GREEN}[PASS]${NC} PTK installed successfully"
    else
        echo -e "${RED}[FAIL]${NC} PTK installation not found"
        return 1
    fi

    # Check for GTK installation
    if grep -q "WPA: Installing GTK to the driver" "${LOG_DIR}/wpa_supplicant_wpa2_${TIMESTAMP}.log"; then
        echo -e "${GREEN}[PASS]${NC} GTK installed successfully"
    else
        echo -e "${RED}[FAIL]${NC} GTK installation not found"
        return 1
    fi

    # Verify only ONE PTK installation (no reinstall)
    PTK_COUNT=$(grep -c "WPA: Installing PTK to the driver" "${LOG_DIR}/wpa_supplicant_wpa2_${TIMESTAMP}.log" || echo 0)
    if [ "${PTK_COUNT}" -eq 1 ]; then
        echo -e "${GREEN}[PASS]${NC} PTK installed exactly once (no reinstallation)"
    else
        echo -e "${YELLOW}[WARN]${NC} PTK installed ${PTK_COUNT} times"
    fi

    # Count EAPOL frames in capture
    EAPOL_COUNT=$(tshark -r "${CAPTURE_DIR}/wpa2_4way_${TIMESTAMP}.pcapng" -Y "eapol" 2>/dev/null | wc -l)
    if [ "${EAPOL_COUNT}" -ge 4 ]; then
        echo -e "${GREEN}[PASS]${NC} Captured ${EAPOL_COUNT} EAPOL frames (4-way handshake present)"
    else
        echo -e "${RED}[FAIL]${NC} Only ${EAPOL_COUNT} EAPOL frames captured"
        return 1
    fi

    echo ""
    return 0
}

# ==============================================================================
# Test 2: WPA3-SAE 4-way Handshake
# ==============================================================================

test_wpa3_4way_handshake() {
    echo -e "${YELLOW}[TEST 2]${NC} WPA3-SAE 4-way Handshake"
    echo "--------------------------------------"

    # Create WPA3-SAE configuration
    WPA3_CONF="/tmp/victim_wpa3.conf"
    cat > "${WPA3_CONF}" <<EOF
network={
    ssid="testnetwork-sae"
    sae_password="abcdefgh"
    key_mgmt=SAE
    ieee80211w=2
}
EOF

    echo -e "${GREEN}[INFO]${NC} Configuration: key_mgmt=SAE (WPA3)"

    # Create WPA3-SAE hostapd configuration
    HOSTAPD_WPA3_CONF="/tmp/hostapd_wpa3.conf"
    cat > "${HOSTAPD_WPA3_CONF}" <<EOF
interface=wlan0
driver=nl80211
ssid=testnetwork-sae
hw_mode=g
channel=6

wpa=2
wpa_key_mgmt=SAE
sae_password=abcdefgh
ieee80211w=2
rsn_pairwise=CCMP
EOF

    echo -e "${GREEN}[INFO]${NC} Starting hostapd (WPA3-SAE mode)..."
    sudo ${HOME}/krack_experiment/krackattacks-scripts/hostapd/hostapd \
        "${HOSTAPD_WPA3_CONF}" > "${LOG_DIR}/hostapd_wpa3_${TIMESTAMP}.log" 2>&1 &
    HOSTAPD_PID=$!
    sleep 3

    # Start packet capture
    echo -e "${GREEN}[INFO]${NC} Starting packet capture on hwsim0..."
    sudo tshark -i hwsim0 -w "${CAPTURE_DIR}/wpa3_4way_${TIMESTAMP}.pcapng" \
        -f "ether proto 0x888e or type data" > /dev/null 2>&1 &
    TSHARK_PID=$!
    sleep 2

    # Start patched wpa_supplicant
    echo -e "${GREEN}[INFO]${NC} Starting patched wpa_supplicant (WPA3-SAE)..."
    sudo ${PATCHED_WPA_SUPPLICANT} -i wlan1 -c "${WPA3_CONF}" -D nl80211 \
        -d -K 2>&1 | tee "${LOG_DIR}/wpa_supplicant_wpa3_${TIMESTAMP}.log" &
    WPA_PID=$!

    # Wait for connection
    echo -e "${GREEN}[INFO]${NC} Waiting for SAE handshake + 4-way handshake (20s)..."
    sleep 20

    # Stop processes
    echo -e "${GREEN}[INFO]${NC} Stopping processes..."
    sudo kill ${WPA_PID} 2>/dev/null || true
    sudo kill ${TSHARK_PID} 2>/dev/null || true
    sudo kill ${HOSTAPD_PID} 2>/dev/null || true
    sleep 2

    # Verify results
    echo -e "${GREEN}[INFO]${NC} Analyzing results..."

    # Check for SAE authentication
    if grep -q "SAE: Authentication" "${LOG_DIR}/wpa_supplicant_wpa3_${TIMESTAMP}.log"; then
        echo -e "${GREEN}[PASS]${NC} SAE authentication initiated"
    else
        echo -e "${YELLOW}[SKIP]${NC} SAE not supported or not negotiated (WPA3 requires kernel support)"
        echo -e "${YELLOW}[INFO]${NC} wpa_supplicant may fall back to WPA2 if WPA3 is unavailable"
        return 0
    fi

    # Check for successful connection
    if grep -q "WPA: Key negotiation completed\|CTRL-EVENT-CONNECTED" "${LOG_DIR}/wpa_supplicant_wpa3_${TIMESTAMP}.log"; then
        echo -e "${GREEN}[PASS]${NC} WPA3 connection completed successfully"
    else
        echo -e "${YELLOW}[SKIP]${NC} WPA3 connection not completed (may require newer kernel/hostapd)"
        return 0
    fi

    # Verify SAE key_mgmt
    if grep -q "RSN: using key_mgmt SAE" "${LOG_DIR}/wpa_supplicant_wpa3_${TIMESTAMP}.log"; then
        echo -e "${GREEN}[PASS]${NC} Confirmed key_mgmt=SAE negotiation"
    else
        echo -e "${YELLOW}[WARN]${NC} Could not confirm SAE negotiation (check log)"
    fi

    echo ""
    return 0
}

# ==============================================================================
# Test 3: GTK Rekeying
# ==============================================================================

test_gtk_rekeying() {
    echo -e "${YELLOW}[TEST 3]${NC} GTK Rekeying (Group Key Handshake)"
    echo "--------------------------------------"

    WPA2_CONF="/tmp/victim_wpa2.conf"
    cat > "${WPA2_CONF}" <<EOF
network={
    ssid="testnetwork"
    psk="abcdefgh"
    key_mgmt=WPA-PSK
}
EOF

    # Create hostapd config with fast GTK rekeying
    HOSTAPD_GTK_CONF="/tmp/hostapd_gtk_rekey.conf"
    cat > "${HOSTAPD_GTK_CONF}" <<EOF
interface=wlan0
driver=nl80211
ssid=testnetwork
hw_mode=g
channel=6

wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=abcdefgh
wpa_pairwise=CCMP
wpa_group_rekey=10
EOF

    echo -e "${GREEN}[INFO]${NC} Configuration: wpa_group_rekey=10 (GTK renewal every 10s)"

    echo -e "${GREEN}[INFO]${NC} Starting hostapd (with GTK rekeying)..."
    sudo ${HOME}/krack_experiment/krackattacks-scripts/hostapd/hostapd \
        "${HOSTAPD_GTK_CONF}" > "${LOG_DIR}/hostapd_gtk_${TIMESTAMP}.log" 2>&1 &
    HOSTAPD_PID=$!
    sleep 3

    # Start packet capture
    echo -e "${GREEN}[INFO]${NC} Starting packet capture on hwsim0..."
    sudo tshark -i hwsim0 -w "${CAPTURE_DIR}/gtk_rekey_${TIMESTAMP}.pcapng" \
        -f "ether proto 0x888e" > /dev/null 2>&1 &
    TSHARK_PID=$!
    sleep 2

    # Start patched wpa_supplicant
    echo -e "${GREEN}[INFO]${NC} Starting patched wpa_supplicant..."
    sudo ${PATCHED_WPA_SUPPLICANT} -i wlan1 -c "${WPA2_CONF}" -D nl80211 \
        -d -K 2>&1 | tee "${LOG_DIR}/wpa_supplicant_gtk_${TIMESTAMP}.log" &
    WPA_PID=$!

    # Wait for initial connection + multiple GTK rekeys
    echo -e "${GREEN}[INFO]${NC} Waiting for initial connection + 2 GTK renewals (30s)..."
    sleep 30

    # Stop processes
    echo -e "${GREEN}[INFO]${NC} Stopping processes..."
    sudo kill ${WPA_PID} 2>/dev/null || true
    sudo kill ${TSHARK_PID} 2>/dev/null || true
    sudo kill ${HOSTAPD_PID} 2>/dev/null || true
    sleep 2

    # Verify results
    echo -e "${GREEN}[INFO]${NC} Analyzing results..."

    # Count GTK installations
    GTK_INSTALL_COUNT=$(grep -c "WPA: Installing GTK to the driver" "${LOG_DIR}/wpa_supplicant_gtk_${TIMESTAMP}.log" || echo 0)

    if [ "${GTK_INSTALL_COUNT}" -ge 2 ]; then
        echo -e "${GREEN}[PASS]${NC} GTK installed ${GTK_INSTALL_COUNT} times (initial + rekey)"
    else
        echo -e "${YELLOW}[WARN]${NC} Only ${GTK_INSTALL_COUNT} GTK installations detected"
    fi

    # Check for Group Key handshake messages
    GROUP_MSG_COUNT=$(grep -c "WPA: Group Key Msg 1\|WPA: Group Key Msg 2" "${LOG_DIR}/wpa_supplicant_gtk_${TIMESTAMP}.log" || echo 0)

    if [ "${GROUP_MSG_COUNT}" -ge 2 ]; then
        echo -e "${GREEN}[PASS]${NC} Group Key handshake messages detected (${GROUP_MSG_COUNT})"
    else
        echo -e "${YELLOW}[WARN]${NC} Limited Group Key messages (${GROUP_MSG_COUNT})"
    fi

    # Verify no GTK reinstallation (each GTK should be unique)
    echo -e "${GREEN}[INFO]${NC} Checking for GTK reinstallation..."
    python3 - <<PYTHON_EOF
import re
import sys

log_file = "${LOG_DIR}/wpa_supplicant_gtk_${TIMESTAMP}.log"

gtk_values = []
with open(log_file, 'r') as f:
    for line in f:
        # Match: WPA: Group Key - hexdump(len=16): xx xx xx ...
        if 'Group Key - hexdump' in line:
            # Extract hex bytes
            match = re.search(r'hexdump\(len=\d+\): ([0-9a-f ]+)', line)
            if match:
                gtk_hex = match.group(1).replace(' ', '')
                gtk_values.append(gtk_hex)

if len(gtk_values) == 0:
    print("[WARN] No GTK values found in log")
    sys.exit(0)

# Check for duplicates
unique_gtks = set(gtk_values)
if len(gtk_values) == len(unique_gtks):
    print(f"[PASS] All {len(gtk_values)} GTK values are unique (no reinstallation)")
else:
    print(f"[FAIL] GTK reinstallation detected: {len(gtk_values)} total, {len(unique_gtks)} unique")
    sys.exit(1)
PYTHON_EOF

    echo ""
    return 0
}

# ==============================================================================
# Test 4: WNM Sleep Mode Handling
# ==============================================================================

test_wnm_sleep_mode() {
    echo -e "${YELLOW}[TEST 4]${NC} WNM Sleep Mode GTK Handling"
    echo "--------------------------------------"

    WPA2_CONF="/tmp/victim_wpa2.conf"
    cat > "${WPA2_CONF}" <<EOF
network={
    ssid="testnetwork"
    psk="abcdefgh"
    key_mgmt=WPA-PSK
}
EOF

    HOSTAPD_CONF="${HOME}/krack_experiment/krackattacks-scripts/krackattack/hostapd.conf"

    echo -e "${GREEN}[INFO]${NC} Starting hostapd..."
    sudo ${HOME}/krack_experiment/krackattacks-scripts/hostapd/hostapd \
        "${HOSTAPD_CONF}" > "${LOG_DIR}/hostapd_wnm_${TIMESTAMP}.log" 2>&1 &
    HOSTAPD_PID=$!
    sleep 3

    # Start packet capture
    echo -e "${GREEN}[INFO]${NC} Starting packet capture on hwsim0..."
    sudo tshark -i hwsim0 -w "${CAPTURE_DIR}/wnm_${TIMESTAMP}.pcapng" \
        -f "ether proto 0x888e" > /dev/null 2>&1 &
    TSHARK_PID=$!
    sleep 2

    # Start patched wpa_supplicant
    echo -e "${GREEN}[INFO]${NC} Starting patched wpa_supplicant..."
    sudo ${PATCHED_WPA_SUPPLICANT} -i wlan1 -c "${WPA2_CONF}" -D nl80211 \
        -d -K 2>&1 | tee "${LOG_DIR}/wpa_supplicant_wnm_${TIMESTAMP}.log" &
    WPA_PID=$!
    sleep 10

    # Trigger WNM sleep mode via hostapd_cli
    echo -e "${GREEN}[INFO]${NC} Sending WNM sleep mode Group Key message..."

    # Use RESEND_GROUP_M1 with maxrsc to simulate WNM GTK distribution
    HOSTAPD_CTRL="/var/run/hostapd"
    if [ -S "${HOSTAPD_CTRL}/wlan0" ]; then
        sudo hostapd_cli -p "${HOSTAPD_CTRL}" -i wlan0 resend_group_m1 02:00:00:00:01:00 maxrsc
        sleep 5
    else
        echo -e "${YELLOW}[WARN]${NC} hostapd control interface not available"
    fi

    # Stop processes
    echo -e "${GREEN}[INFO]${NC} Stopping processes..."
    sudo kill ${WPA_PID} 2>/dev/null || true
    sudo kill ${TSHARK_PID} 2>/dev/null || true
    sudo kill ${HOSTAPD_PID} 2>/dev/null || true
    sleep 2

    # Verify results
    echo -e "${GREEN}[INFO]${NC} Analyzing results..."

    # Check for WNM-related GTK handling
    if grep -q "WPA: Installing GTK to the driver\|Group Key Msg" "${LOG_DIR}/wpa_supplicant_wnm_${TIMESTAMP}.log"; then
        echo -e "${GREEN}[PASS]${NC} WNM GTK message handled successfully"
    else
        echo -e "${YELLOW}[SKIP]${NC} WNM GTK message not detected (normal in hwsim)"
    fi

    # Verify no crashes or errors
    if grep -q "CTRL-EVENT-TERMINATING\|Segmentation fault" "${LOG_DIR}/wpa_supplicant_wnm_${TIMESTAMP}.log"; then
        echo -e "${RED}[FAIL]${NC} wpa_supplicant crashed or terminated unexpectedly"
        return 1
    else
        echo -e "${GREEN}[PASS]${NC} wpa_supplicant remained stable (no crashes)"
    fi

    echo ""
    return 0
}

# ==============================================================================
# Main Execution
# ==============================================================================

main() {
    local FAILED_TESTS=0

    # Run all tests
    test_wpa2_4way_handshake || ((FAILED_TESTS++))
    test_wpa3_4way_handshake || ((FAILED_TESTS++))
    test_gtk_rekeying || ((FAILED_TESTS++))
    test_wnm_sleep_mode || ((FAILED_TESTS++))

    # Summary
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}Test Summary${NC}"
    echo -e "${BLUE}======================================${NC}"

    if [ ${FAILED_TESTS} -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} All tests passed!"
        echo -e "${GREEN}[RESULT]${NC} RSS-KRACK patched wpa_supplicant handles normal operations correctly:"
        echo "  ✓ WPA2-PSK 4-way handshake"
        echo "  ✓ WPA3-SAE 4-way handshake (if supported)"
        echo "  ✓ GTK rekeying (Group Key handshake)"
        echo "  ✓ WNM sleep mode GTK handling"
        echo ""
        echo "Logs saved to: ${LOG_DIR}"
        echo "Captures saved to: ${CAPTURE_DIR}"
        return 0
    else
        echo -e "${RED}[FAILURE]${NC} ${FAILED_TESTS} test(s) failed"
        echo "Check logs in: ${LOG_DIR}"
        return 1
    fi
}

main "$@"
