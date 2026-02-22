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
# Live integration tests for ddns-update.sh
#
# Performs real DNS updates against a live nameserver using TSIG key
# authentication, then verifies the results with dig.
#
# Configuration is read from tests/live_tests.conf (gitignored).
# See tests/live_tests.conf.example for the expected format.
#
# Usage:  ./tests/live_tests.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DDNS="${PROJECT_DIR}/ddns-update.sh"
CONF="${SCRIPT_DIR}/live_tests.conf"

# ---------------------------------------------------------------------------
# Load configuration
# ---------------------------------------------------------------------------

if [ ! -f "${CONF}" ]; then
    echo "ERR: Config file not found: ${CONF}"
    echo "     Copy tests/live_tests.conf.example to tests/live_tests.conf"
    echo "     and fill in your nameserver, key file, and test domain."
    exit 1
fi

source "${CONF}"

for var in LIVE_NAMESERVER LIVE_KEYFILE LIVE_DOMAIN LIVE_PTR_NET LIVE_PTR6_PREFIX; do
    if [ -z "${!var:-}" ]; then
        echo "ERR: ${var} is not set in ${CONF}"
        exit 1
    fi
done

if [ ! -r "${LIVE_KEYFILE}" ]; then
    echo "ERR: Key file not readable: ${LIVE_KEYFILE}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Preflight — verify nameserver is reachable
# ---------------------------------------------------------------------------

if ! dig +short +time=3 +tries=1 @"${LIVE_NAMESERVER}" SOA "${LIVE_DOMAIN}" >/dev/null 2>&1; then
    echo "ERR: Cannot reach nameserver ${LIVE_NAMESERVER} — is it up?"
    exit 1
fi

# ---------------------------------------------------------------------------
# Counters and helpers
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
TOTAL=0

TEST_IP_A="192.0.2.1"
TEST_IP_A2="192.0.2.2"
# Use dig's canonical IPv6 format (no :: for single zero groups) so that
# string comparisons in ddns-update.sh idempotency checks match dig output.
TEST_IP_AAAA1="${LIVE_PTR6_PREFIX}:0:1"
TEST_IP_AAAA2="${LIVE_PTR6_PREFIX}:0:2"
CNAME_TARGET="cname-target.${LIVE_DOMAIN}"
TEST_PTR_IP1="${LIVE_PTR_NET}.1"
TEST_PTR_IP2="${LIVE_PTR_NET}.2"

# Build reverse arpa names from the /24 prefix
_ptr_reversed=$(echo "${LIVE_PTR_NET}" | awk -F. '{print $3"."$2"."$1}')
TEST_PTR_REV1="1.${_ptr_reversed}.in-addr.arpa"
TEST_PTR_REV2="2.${_ptr_reversed}.in-addr.arpa"

# Build IPv6 reverse arpa names — expand, strip colons, reverse nibbles
_expand_ipv6() {
    local ip=$1
    echo "$ip" | grep -qs "^:" && ip="0${ip}"
    if echo "$ip" | grep -qs "::"; then
        local colons=$(echo "$ip" | sed 's/[^:]//g')
        local missing=$(echo ":::::::::" | sed "s/$colons//")
        local expanded=$(echo "$missing" | sed 's/:/:0/g')
        ip=$(echo "$ip" | sed "s/::/$expanded/")
    fi
    local blocks=$(echo "$ip" | grep -o "[0-9a-f]\+")
    set $blocks
    printf "%04x%04x%04x%04x%04x%04x%04x%04x" \
        $(( 0x$1 )) $(( 0x$2 )) $(( 0x$3 )) $(( 0x$4 )) \
        $(( 0x$5 )) $(( 0x$6 )) $(( 0x$7 )) $(( 0x$8 ))
}

_ipv6_to_arpa() {
    local hex=$(_expand_ipv6 "$1")
    echo "$hex" | awk '{
        for (i=length($0); i>0; i--)
            printf "%s.", substr($0,i,1)
        print "ip6.arpa"
    }'
}

TEST_PTR6_REV1=$(_ipv6_to_arpa "${TEST_IP_AAAA1}")
TEST_PTR6_REV2=$(_ipv6_to_arpa "${TEST_IP_AAAA2}")

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

assert_empty() {
    local desc=$1 actual=$2
    TOTAL=$((TOTAL + 1))
    if [ -z "$actual" ]; then
        echo "  PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${desc}"
        echo "        expected empty, got: '${actual}'"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc=$1 needle=$2 haystack=$3
    TOTAL=$((TOTAL + 1))
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

# Query a DNS record and return the value (empty if not found).
dns_lookup() {
    local name=$1 type=$2
    dig +short +time=5 +tries=2 "${name}" "${type}" @"${LIVE_NAMESERVER}" | head -1
}

# Pause briefly to let the nameserver process the update.
settle() {
    sleep 1
}

# ---------------------------------------------------------------------------
# Cleanup — ensure a clean slate before and after tests
# ---------------------------------------------------------------------------

cleanup() {
    echo ""
    echo "-- Cleanup --"
    "${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -D -F >/dev/null 2>&1 || true
    "${DDNS}" -h "cname-live.${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -D -F >/dev/null 2>&1 || true
    "${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r -D -F "${TEST_PTR_IP1}" >/dev/null 2>&1 || true
    "${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r -D -F "${TEST_PTR_IP2}" >/dev/null 2>&1 || true
    "${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -D -F >/dev/null 2>&1 || true
    # Clean up both :: and :0: forms in case either was left behind
    "${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r -D -F "${TEST_IP_AAAA1}" >/dev/null 2>&1 || true
    "${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r -D -F "${TEST_IP_AAAA2}" >/dev/null 2>&1 || true
    settle
}

trap cleanup EXIT
cleanup

# ---------------------------------------------------------------------------
# Test 1: Create an A record
# ---------------------------------------------------------------------------
echo ""
echo "== A record: create =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -v -F "${TEST_IP_A}" 2>&1)
assert_contains "ddns-update reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" A)
assert_eq "A record resolves to ${TEST_IP_A}" "${TEST_IP_A}" "$result"

# ---------------------------------------------------------------------------
# Test 2: Idempotency — same IP, no force
# ---------------------------------------------------------------------------
echo ""
echo "== A record: idempotent (no change) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" "${TEST_IP_A}" 2>&1)
assert_contains "Reports record unchanged" "Record unchanged" "$output"

# ---------------------------------------------------------------------------
# Test 3: Update an A record to a new IP
# ---------------------------------------------------------------------------
echo ""
echo "== A record: update =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -v "${TEST_IP_A2}" 2>&1)
assert_contains "ddns-update reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" A)
assert_eq "A record updated to ${TEST_IP_A2}" "${TEST_IP_A2}" "$result"

# ---------------------------------------------------------------------------
# Test 4: Force update with same IP
# ---------------------------------------------------------------------------
echo ""
echo "== A record: force update =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -F "${TEST_IP_A2}" 2>&1)
assert_contains "Force update reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" A)
assert_eq "A record still ${TEST_IP_A2} after force" "${TEST_IP_A2}" "$result"

# ---------------------------------------------------------------------------
# Test 5: Delete an A record
# ---------------------------------------------------------------------------
echo ""
echo "== A record: delete =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -D 2>&1)
assert_contains "Delete reports success" "Delete successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" A)
assert_empty "A record deleted" "$result"

# ---------------------------------------------------------------------------
# Test 6: Delete non-existent record (no-op)
# ---------------------------------------------------------------------------
echo ""
echo "== A record: delete non-existent (no-op) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -D 2>&1)
assert_contains "Nothing to delete" "Nothing to delete" "$output"

# ---------------------------------------------------------------------------
# Test 7: CNAME create and delete
# ---------------------------------------------------------------------------
echo ""
echo "== CNAME record: create =="

output=$("${DDNS}" -h "cname-live.${LIVE_DOMAIN}" -c "${CNAME_TARGET}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -v -F 2>&1)
assert_contains "CNAME create reports success" "Update successful" "$output"

settle
result=$(dns_lookup "cname-live.${LIVE_DOMAIN}" CNAME)
# dig returns CNAME with trailing dot
assert_eq "CNAME resolves to target" "${CNAME_TARGET}." "$result"

echo ""
echo "== CNAME record: delete =="

output=$("${DDNS}" -h "cname-live.${LIVE_DOMAIN}" -c "${CNAME_TARGET}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -D 2>&1)
assert_contains "CNAME delete reports success" "Delete successful" "$output"

settle
result=$(dns_lookup "cname-live.${LIVE_DOMAIN}" CNAME)
assert_empty "CNAME record deleted" "$result"

# ---------------------------------------------------------------------------
# Test 8: PTR record create
# ---------------------------------------------------------------------------
echo ""
echo "== PTR record: create =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r -v -F "${TEST_PTR_IP1}" 2>&1)
assert_contains "PTR create reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR_REV1}" PTR)
# dig returns PTR with trailing dot
assert_eq "PTR ${TEST_PTR_REV1} points to ${LIVE_DOMAIN}" "${LIVE_DOMAIN}." "$result"

# ---------------------------------------------------------------------------
# Test 9: PTR record idempotency
# ---------------------------------------------------------------------------
echo ""
echo "== PTR record: idempotent (no change) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r "${TEST_PTR_IP1}" 2>&1)
assert_contains "PTR reports record unchanged" "Record unchanged" "$output"

# ---------------------------------------------------------------------------
# Test 10: Delete first PTR, create second at different IP
# ---------------------------------------------------------------------------
echo ""
echo "== PTR record: delete first, create at new IP =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r -D "${TEST_PTR_IP1}" 2>&1)
assert_contains "First PTR delete reports success" "Delete successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR_REV1}" PTR)
assert_empty "First PTR ${TEST_PTR_REV1} removed" "$result"

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r -v -F "${TEST_PTR_IP2}" 2>&1)
assert_contains "Second PTR create reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR_REV2}" PTR)
assert_eq "PTR ${TEST_PTR_REV2} points to ${LIVE_DOMAIN}" "${LIVE_DOMAIN}." "$result"

# ---------------------------------------------------------------------------
# Test 11: PTR record delete
# ---------------------------------------------------------------------------
echo ""
echo "== PTR record: delete =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r -D "${TEST_PTR_IP2}" 2>&1)
assert_contains "PTR delete reports success" "Delete successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR_REV2}" PTR)
assert_empty "PTR record deleted" "$result"

# ---------------------------------------------------------------------------
# Test 12: PTR delete non-existent (no-op)
# ---------------------------------------------------------------------------
echo ""
echo "== PTR record: delete non-existent (no-op) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -r -D "${TEST_PTR_IP2}" 2>&1)
assert_contains "PTR nothing to delete" "Nothing to delete" "$output"

# ---------------------------------------------------------------------------
# Test 13: AAAA record create
# ---------------------------------------------------------------------------
echo ""
echo "== AAAA record: create =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -v -F "${TEST_IP_AAAA1}" 2>&1)
assert_contains "AAAA create reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" AAAA)
assert_eq "AAAA record resolves to ${TEST_IP_AAAA1}" "${TEST_IP_AAAA1}" "$result"

# ---------------------------------------------------------------------------
# Test 14: AAAA record idempotency
# ---------------------------------------------------------------------------
echo ""
echo "== AAAA record: idempotent (no change) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 "${TEST_IP_AAAA1}" 2>&1)
assert_contains "AAAA reports record unchanged" "Record unchanged" "$output"

# ---------------------------------------------------------------------------
# Test 15: AAAA record update
# ---------------------------------------------------------------------------
echo ""
echo "== AAAA record: update =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -v "${TEST_IP_AAAA2}" 2>&1)
assert_contains "AAAA update reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" AAAA)
assert_eq "AAAA record updated to ${TEST_IP_AAAA2}" "${TEST_IP_AAAA2}" "$result"

# ---------------------------------------------------------------------------
# Test 16: AAAA record force update
# ---------------------------------------------------------------------------
echo ""
echo "== AAAA record: force update =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -F "${TEST_IP_AAAA2}" 2>&1)
assert_contains "AAAA force update reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" AAAA)
assert_eq "AAAA record still ${TEST_IP_AAAA2} after force" "${TEST_IP_AAAA2}" "$result"

# ---------------------------------------------------------------------------
# Test 17: AAAA record delete
# ---------------------------------------------------------------------------
echo ""
echo "== AAAA record: delete =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -D 2>&1)
assert_contains "AAAA delete reports success" "Delete successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" AAAA)
assert_empty "AAAA record deleted" "$result"

# ---------------------------------------------------------------------------
# Test 18: AAAA delete non-existent (no-op)
# ---------------------------------------------------------------------------
echo ""
echo "== AAAA record: delete non-existent (no-op) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -D 2>&1)
assert_contains "AAAA nothing to delete" "Nothing to delete" "$output"

# ---------------------------------------------------------------------------
# Test 19: IPv6 PTR record create
# ---------------------------------------------------------------------------
echo ""
echo "== IPv6 PTR record: create =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r -v -F "${TEST_IP_AAAA1}" 2>&1)
assert_contains "IPv6 PTR create reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR6_REV1}" PTR)
assert_eq "IPv6 PTR points to ${LIVE_DOMAIN}" "${LIVE_DOMAIN}." "$result"

# ---------------------------------------------------------------------------
# Test 20: IPv6 PTR record idempotency
# ---------------------------------------------------------------------------
echo ""
echo "== IPv6 PTR record: idempotent (no change) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r "${TEST_IP_AAAA1}" 2>&1)
assert_contains "IPv6 PTR reports record unchanged" "Record unchanged" "$output"

# ---------------------------------------------------------------------------
# Test 21: IPv6 PTR delete first, create at new address
# ---------------------------------------------------------------------------
echo ""
echo "== IPv6 PTR record: delete first, create at new address =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r -D "${TEST_IP_AAAA1}" 2>&1)
assert_contains "First IPv6 PTR delete reports success" "Delete successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR6_REV1}" PTR)
assert_empty "First IPv6 PTR removed" "$result"

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r -v -F "${TEST_IP_AAAA2}" 2>&1)
assert_contains "Second IPv6 PTR create reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR6_REV2}" PTR)
assert_eq "IPv6 PTR at ::2 points to ${LIVE_DOMAIN}" "${LIVE_DOMAIN}." "$result"

# ---------------------------------------------------------------------------
# Test 22: IPv6 PTR record delete
# ---------------------------------------------------------------------------
echo ""
echo "== IPv6 PTR record: delete =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r -D "${TEST_IP_AAAA2}" 2>&1)
assert_contains "IPv6 PTR delete reports success" "Delete successful" "$output"

settle
result=$(dns_lookup "${TEST_PTR6_REV2}" PTR)
assert_empty "IPv6 PTR record deleted" "$result"

# ---------------------------------------------------------------------------
# Test 23: IPv6 PTR delete non-existent (no-op)
# ---------------------------------------------------------------------------
echo ""
echo "== IPv6 PTR record: delete non-existent (no-op) =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -r -D "${TEST_IP_AAAA2}" 2>&1)
assert_contains "IPv6 PTR nothing to delete" "Nothing to delete" "$output"

# ---------------------------------------------------------------------------
# Test 24: -I INTERFACE — auto-detect external IP via interface
# ---------------------------------------------------------------------------
echo ""
echo "== Interface: auto-detect external IP via -I =="

# No positional IP — the script fetches the external IP from ifconfig.me
# using the specified interface, then creates an A record with it.
output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -I "${LIVE_INTERFACE}" -v -F 2>&1)
assert_contains "-I auto-detect reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" A)
# We don't know the external IP in advance, but it must be a valid IPv4
TOTAL=$((TOTAL + 1))
if [[ "$result" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  PASS: -I auto-detected A record is valid IPv4 (${result})"
    PASS=$((PASS + 1))
else
    echo "  FAIL: -I auto-detected A record is not valid IPv4"
    echo "        got: '${result}'"
    FAIL=$((FAIL + 1))
fi

# Clean up the auto-detected A record
"${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -D -F >/dev/null 2>&1 || true
settle

# ---------------------------------------------------------------------------
# Test 25: -I INTERFACE -6 — auto-detect external IPv6 via interface
# ---------------------------------------------------------------------------
echo ""
echo "== Interface: auto-detect external IPv6 via -I =="

output=$("${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -I "${LIVE_INTERFACE}" -6 -v -F 2>&1)
assert_contains "-I auto-detect IPv6 reports success" "Update successful" "$output"

settle
result=$(dns_lookup "${LIVE_DOMAIN}" AAAA)
TOTAL=$((TOTAL + 1))
if [[ "$result" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
    echo "  PASS: -I auto-detected AAAA record is valid IPv6 (${result})"
    PASS=$((PASS + 1))
else
    echo "  FAIL: -I auto-detected AAAA record is not valid IPv6"
    echo "        got: '${result}'"
    FAIL=$((FAIL + 1))
fi

# Clean up the auto-detected AAAA record
"${DDNS}" -h "${LIVE_DOMAIN}" -n "${LIVE_NAMESERVER}" -k "${LIVE_KEYFILE}" -6 -D -F >/dev/null 2>&1 || true
settle

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================="
echo "Live results: ${PASS} passed, ${FAIL} failed, ${TOTAL} total"
echo "=============================="

[ ${FAIL} -eq 0 ] && exit 0 || exit 1
