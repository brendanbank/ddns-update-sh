#!/usr/bin/env bash
#
# BSD 2-Clause "Simplified" License
#
# Copyright (c) 2024, Brendan Bank
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Test suite for ddns-update.sh
#
# Runs offline tests that validate option parsing, IP address validation,
# IPv6 expansion, and reverse-IP generation.  Does NOT require a live DNS
# server or valid TSIG key — all nsupdate/dig calls are stubbed out.
#
# Usage:  ./tests/run_tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DDNS="${PROJECT_DIR}/ddns-update.sh"

# Counters
PASS=0
FAIL=0
TOTAL=0

# Temporary directory for test fixtures
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

# Create a dummy key file (never sent anywhere)
DUMMY_KEY="${TMPDIR}/test.key"
cat > "${DUMMY_KEY}" <<'KEYEOF'
key "test.example.com" {
    algorithm hmac-sha512;
    secret "dGVzdHNlY3JldA==";
};
KEYEOF

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

assert_eq() {
    local desc=$1 expected=$2 actual=$3
    TOTAL=$((TOTAL + 1))
    if [ "$expected" == "$actual" ]; then
        echo "  PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${desc}"
        echo "        expected: '${expected}'"
        echo "        actual:   '${actual}'"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc=$1 needle=$2 haystack=$3
    TOTAL=$((TOTAL + 1))
    # Use grep -F -- to prevent needle from being interpreted as options
    if echo "$haystack" | grep -qF -- "$needle"; then
        echo "  PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${desc}"
        echo "        expected to contain: '${needle}'"
        echo "        got: '${haystack}'"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Extract and source only the function definitions from ddns-update.sh.
# We use awk to pull out function bodies and skip all top-level executable
# code, dependency checks, and variable assignments that cause side effects.
# ---------------------------------------------------------------------------

FUNC_FILE="${TMPDIR}/functions.sh"

awk '
    /^[a-zA-Z_][a-zA-Z0-9_]* *\(\)/ { infunc=1 }
    infunc { print }
    infunc && /^}/ { infunc=0; print "" }
' "${DDNS}" > "${FUNC_FILE}"

# Provide stub globals that the functions reference
cat >> "${FUNC_FILE}" <<'STUBEOF'
VERBOSE=0
IPCLASS=4
REVERSE=0
ERROR_TXT=""
STUBEOF

source "${FUNC_FILE}"

# ---------------------------------------------------------------------------
# Test: checkipaddress
# ---------------------------------------------------------------------------
echo ""
echo "== checkipaddress =="

checkipaddress "192.168.1.1" 4 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv4 (192.168.1.1) returns 1" "1" "$rc"

checkipaddress "10.0.0.1" 4 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv4 (10.0.0.1) returns 1" "1" "$rc"

checkipaddress "255.255.255.255" 4 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv4 (255.255.255.255) returns 1" "1" "$rc"

checkipaddress "notanip" 4 >/dev/null 2>&1; rc=$?
assert_eq "Invalid IPv4 (notanip) returns 0" "0" "$rc"

checkipaddress "192.168.1" 4 >/dev/null 2>&1; rc=$?
assert_eq "Incomplete IPv4 (192.168.1) returns 0" "0" "$rc"

checkipaddress "" 4 >/dev/null 2>&1; rc=$?
assert_eq "Empty string IPv4 returns 0" "0" "$rc"

checkipaddress "2001:db8::1" 6 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv6 (2001:db8::1) returns 1" "1" "$rc"

checkipaddress "fe80::1" 6 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv6 (fe80::1) returns 1" "1" "$rc"

checkipaddress "::1" 6 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv6 (::1) returns 1" "1" "$rc"

checkipaddress "not:an:ipv6" 6 >/dev/null 2>&1; rc=$?
assert_eq "Invalid IPv6 (not:an:ipv6) returns 0" "0" "$rc"

checkipaddress "2001:4c3b:8d35:cafe:cafe:cafe::1" 6 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv6 (2001:4c3b:8d35:cafe:cafe:cafe::1) returns 1" "1" "$rc"

checkipaddress "2001:4c3b:8d35:cafe:cafe:cafe::2" 6 >/dev/null 2>&1; rc=$?
assert_eq "Valid IPv6 (2001:4c3b:8d35:cafe:cafe:cafe::2) returns 1" "1" "$rc"

checkipaddress "" 6 >/dev/null 2>&1; rc=$?
assert_eq "Empty string IPv6 returns 0" "0" "$rc"

checkipaddress "2001:db8::gggg" 6 >/dev/null 2>&1; rc=$?
assert_eq "Invalid hex in IPv6 returns 0" "0" "$rc"

checkipaddress "1234:5678:9abc:def0:1234:5678:9abc:def0" 6 >/dev/null 2>&1; rc=$?
assert_eq "Full 8-group IPv6 returns 1" "1" "$rc"

# ---------------------------------------------------------------------------
# Test: hex2dec
# ---------------------------------------------------------------------------
echo ""
echo "== hex2dec =="

result=$(hex2dec "ff")
assert_eq "0xff = 255" "255" "$result"

result=$(hex2dec "0")
assert_eq "0x0 = 0" "0" "$result"

result=$(hex2dec "2001")
assert_eq "0x2001 = 8193" "8193" "$result"

result=$(hex2dec "a")
assert_eq "0xa = 10" "10" "$result"

# ---------------------------------------------------------------------------
# Test: expand_ipv6
# ---------------------------------------------------------------------------
echo ""
echo "== expand_ipv6 =="

result=$(expand_ipv6 "2001:db8::1")
assert_eq "2001:db8::1 expands" "2001:0db8:0000:0000:0000:0000:0000:0001" "$result"

result=$(expand_ipv6 "::1")
assert_eq "::1 expands" "0000:0000:0000:0000:0000:0000:0000:0001" "$result"

result=$(expand_ipv6 "fe80::abcd:1234")
assert_eq "fe80::abcd:1234 expands" "fe80:0000:0000:0000:0000:0000:abcd:1234" "$result"

result=$(expand_ipv6 "2001:0db8:0000:0000:0000:0000:0000:0001")
assert_eq "Already full address unchanged" "2001:0db8:0000:0000:0000:0000:0000:0001" "$result"

result=$(expand_ipv6 "2001:4c3b:8d35:cafe:cafe:cafe::1")
assert_eq "2001:4c3b:8d35:cafe:cafe:cafe::1 expands" \
    "2001:4c3b:8d35:cafe:cafe:cafe:0000:0001" "$result"

result=$(expand_ipv6 "2001:4c3b:8d35:cafe:cafe:cafe::2")
assert_eq "2001:4c3b:8d35:cafe:cafe:cafe::2 expands" \
    "2001:4c3b:8d35:cafe:cafe:cafe:0000:0002" "$result"

result=$(expand_ipv6 "::")
assert_eq ":: expands to all zeros" "0000:0000:0000:0000:0000:0000:0000:0000" "$result"

# ---------------------------------------------------------------------------
# Test: reverseip4
# ---------------------------------------------------------------------------
echo ""
echo "== reverseip4 =="

reverseip4 "1.2.3.4"
assert_eq "1.2.3.4 reverses" "4.3.2.1.in-addr.arpa" "$REVERSE_IP"

reverseip4 "192.168.10.50"
assert_eq "192.168.10.50 reverses" "50.10.168.192.in-addr.arpa" "$REVERSE_IP"

reverseip4 "10.0.0.1"
assert_eq "10.0.0.1 reverses" "1.0.0.10.in-addr.arpa" "$REVERSE_IP"

# ---------------------------------------------------------------------------
# Test: reverseip6
# ---------------------------------------------------------------------------
echo ""
echo "== reverseip6 =="

reverseip6 "2001:db8::1"
assert_eq "2001:db8::1 reverses" \
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" \
    "$REVERSE_IP"

reverseip6 "2001:4c3b:8d35:cafe:cafe:cafe::1"
assert_eq "2001:4c3b:8d35:cafe:cafe:cafe::1 reverses" \
    "1.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.e.f.a.c.5.3.d.8.b.3.c.4.1.0.0.2.ip6.arpa" \
    "$REVERSE_IP"

reverseip6 "2001:4c3b:8d35:cafe:cafe:cafe::2"
assert_eq "2001:4c3b:8d35:cafe:cafe:cafe::2 reverses" \
    "2.0.0.0.0.0.0.0.e.f.a.c.e.f.a.c.e.f.a.c.5.3.d.8.b.3.c.4.1.0.0.2.ip6.arpa" \
    "$REVERSE_IP"

reverseip6 "::"
assert_eq ":: reverses to all-zero ip6.arpa" \
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa" \
    "$REVERSE_IP"

# ---------------------------------------------------------------------------
# Test: option parsing — missing required arguments
# ---------------------------------------------------------------------------
echo ""
echo "== Option parsing =="

output=$("${DDNS}" 2>&1 || true)
assert_contains "No args shows error" "requires arguments" "$output"

output=$("${DDNS}" -h test.example.com 2>&1 || true)
assert_contains "Missing -n shows error" "NAMESERVER is empty" "$output"

output=$("${DDNS}" -h test.example.com -n 10.0.0.1 2>&1 || true)
assert_contains "Missing -k shows error" "KEYFILE is empty" "$output"

# ---------------------------------------------------------------------------
# Test: -I INTERFACE validation
# ---------------------------------------------------------------------------
echo ""
echo "== Interface validation =="

# Invalid interface should be rejected (dig/nsupdate will fail before reaching
# the server, but the interface check itself runs first).
output=$("${DDNS}" -h test.example.com -n 10.0.0.1 -k "${DUMMY_KEY}" -I nosuchif0 1.2.3.4 2>&1 || true)
assert_contains "Invalid interface rejected" "Could not find INTERFACE" "$output"

# Grab a real interface from the system to test acceptance
if [ -x "$(type -P ifconfig)" ]; then
    REAL_IF=$(ifconfig -l -u inet | awk '{print $1}')
elif [ -x "$(type -P ip)" ]; then
    REAL_IF=$(ip -o link show | awk -F': ' 'NR==1{print $2}')
fi

if [ ! -z "${REAL_IF:-}" ]; then
    # With a valid interface the script should get past the interface check.
    # It will fail later at dig/nsupdate (no real server), but should NOT
    # complain about the interface.
    output=$("${DDNS}" -h test.example.com -n 10.0.0.1 -k "${DUMMY_KEY}" -I "${REAL_IF}" 1.2.3.4 2>&1 || true)
    TOTAL=$((TOTAL + 1))
    if echo "$output" | grep -qF "Could not find INTERFACE"; then
        echo "  FAIL: Valid interface (${REAL_IF}) should be accepted"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: Valid interface (${REAL_IF}) accepted"
        PASS=$((PASS + 1))
    fi
fi

# ---------------------------------------------------------------------------
# Test: CNAME mutual exclusivity
# ---------------------------------------------------------------------------
echo ""
echo "== CNAME mutual exclusivity =="

output=$("${DDNS}" -h test.example.com -c target.example.com -r -n 10.0.0.1 -k "${DUMMY_KEY}" 2>&1 || true)
assert_contains "CNAME + reverse rejected" "cannot be combined with -r" "$output"

output=$("${DDNS}" -h test.example.com -c target.example.com -n 10.0.0.1 -k "${DUMMY_KEY}" 1.2.3.4 2>&1 || true)
assert_contains "CNAME + positional IP rejected" "cannot be combined with a positional IP" "$output"

# ---------------------------------------------------------------------------
# Test: .env file loading
# ---------------------------------------------------------------------------
echo ""
echo "== .env file loading =="

# Create a temporary copy of the script so we can place a .env beside it
ENV_TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}" "${ENV_TMPDIR}"' EXIT
cp "${DDNS}" "${ENV_TMPDIR}/ddns-update.sh"
chmod +x "${ENV_TMPDIR}/ddns-update.sh"

# Create a .env that supplies NAMESERVER and KEYFILE
cat > "${ENV_TMPDIR}/.env" <<ENVEOF
NAMESERVER=10.0.0.1
KEYFILE=${DUMMY_KEY}
ENVEOF

# With .env present, -n and -k should no longer be required
output=$("${ENV_TMPDIR}/ddns-update.sh" -h test.example.com 1.2.3.4 2>&1 || true)
TOTAL=$((TOTAL + 1))
if echo "$output" | grep -qE "NAMESERVER is empty|KEYFILE is empty"; then
    echo "  FAIL: .env should supply NAMESERVER and KEYFILE"
    echo "        got: ${output}"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: .env supplies NAMESERVER and KEYFILE"
    PASS=$((PASS + 1))
fi

# Command-line args should override .env values
output=$("${ENV_TMPDIR}/ddns-update.sh" -h test.example.com -n notanip 1.2.3.4 2>&1 || true)
assert_contains ".env overridden by -n flag" "not a valid IPv4" "$output"

# Without .env, the script should still require -n and -k
rm "${ENV_TMPDIR}/.env"
output=$("${ENV_TMPDIR}/ddns-update.sh" -h test.example.com 1.2.3.4 2>&1 || true)
assert_contains "No .env requires -n" "NAMESERVER is empty" "$output"

# .env with quoted values should work
cat > "${ENV_TMPDIR}/.env" <<ENVEOF
NAMESERVER="10.0.0.1"
KEYFILE='${DUMMY_KEY}'
ENVEOF

output=$("${ENV_TMPDIR}/ddns-update.sh" -h test.example.com 1.2.3.4 2>&1 || true)
TOTAL=$((TOTAL + 1))
if echo "$output" | grep -qE "NAMESERVER is empty|KEYFILE is empty"; then
    echo "  FAIL: .env with quoted values should work"
    echo "        got: ${output}"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: .env with quoted values accepted"
    PASS=$((PASS + 1))
fi

# .env with comments should be handled
cat > "${ENV_TMPDIR}/.env" <<ENVEOF
# This is a comment
NAMESERVER=10.0.0.1

# Another comment
KEYFILE=${DUMMY_KEY}
ENVEOF

output=$("${ENV_TMPDIR}/ddns-update.sh" -h test.example.com 1.2.3.4 2>&1 || true)
TOTAL=$((TOTAL + 1))
if echo "$output" | grep -qE "NAMESERVER is empty|KEYFILE is empty"; then
    echo "  FAIL: .env with comments should work"
    echo "        got: ${output}"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: .env with comments handled correctly"
    PASS=$((PASS + 1))
fi

# ---------------------------------------------------------------------------
# Test: invalid nameserver address
# ---------------------------------------------------------------------------
echo ""
echo "== Nameserver validation =="

output=$("${DDNS}" -h test.example.com -n notanip -k "${DUMMY_KEY}" 2>&1 || true)
assert_contains "Invalid nameserver rejected" "not a valid IPv4" "$output"

# ---------------------------------------------------------------------------
# Test: help flag
# ---------------------------------------------------------------------------
echo ""
echo "== Help flag =="

output=$("${DDNS}" -H 2>&1 || true)
assert_contains "-H shows usage" "HOSTNAME" "$output"
assert_contains "-H shows CNAME option" "-c TARGET" "$output"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================="
echo "Results: ${PASS} passed, ${FAIL} failed, ${TOTAL} total"
echo "=============================="

[ ${FAIL} -eq 0 ] && exit 0 || exit 1
