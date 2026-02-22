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
# ddns-update.sh - Dynamic DNS update client using nsupdate
#
# Updates DNS resource records (A, AAAA, CNAME, PTR) on a BIND-compatible
# nameserver using TSIG key authentication. Can auto-detect the external IP
# address via http://ifconfig.me or accept one on the command line.
#
# Examples:
#   # Update A record with auto-detected external IPv4:
#   ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key
#
#   # Update AAAA record on a specific interface:
#   ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key -6 -I eth0
#
#   # Create a CNAME record:
#   ddns-update.sh -h alias.example.com -c target.example.com -n 10.0.0.1 -k /path/to/key
#
#   # Set reverse PTR record:
#   ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key -r 1.2.3.4
#
#   # Delete an existing record:
#   ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key -D

script_name=$(basename "$0")

# ---------------------------------------------------------------------------
# Detect available system commands for interface enumeration
# ---------------------------------------------------------------------------

IFCONFIG_CMD=$(type -P ifconfig)
IFCONFIG_CMD_EXEC="${IFCONFIG_CMD} -l -u inet"
IP_CMD=$(type -P ip)
IP_CMD_EXEC="${IP_CMD} -o link show"

# Buffer for verbose messages; printed on error even when not in verbose mode
ERROR_TXT=""

# ---------------------------------------------------------------------------
# Logging and error helpers
# ---------------------------------------------------------------------------

# Print an error message with usage information and exit.
echoerr_usage() {
    echo "ERR: $@" 1>&2
    echo "${usage}" 1>&2
    exit 1
}

# Print an error message and exit.
echoerr() {
    echo "ERR: $@" 1>&2
    exit 1
}

# Print a message when verbose mode is enabled.  Otherwise buffer it in
# ERROR_TXT so it can be included in error output if something goes wrong.
echoverbose() {
    if [ "${VERBOSE}" == 1 ]; then
        echo "$@"
    else
        VERBOSE_TXT="$@"
        ERROR_TXT="${ERROR_TXT}
${VERBOSE_TXT}"
    fi
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

# Locate an HTTP fetcher (curl preferred).  The result is stored as
# "name:/path/to/binary" so we can branch on the name later.
FETCHAPPS="curl"

for app in $FETCHAPPS; do
    FETCHAPP="$(type -P "$app")"
    [ ! -z "$FETCHAPP" ] && FETCHAPP="$app:$FETCHAPP" && break
done

[ -z "$FETCHAPP" ] && echoerr "could not find http fetching app(s): $FETCHAPPS"

NSUPDATE_APP="$(type -P "nsupdate")"
[ -z "$NSUPDATE_APP" ] && echoerr "could not find executable 'nsupdate' in PATH"

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

# Build the command line for the HTTP fetcher.  Supports curl, fetch and wget.
# Sets the global APP_EXEC_ARG variable used later to query http://ifconfig.me.
getfetchapp() {
    APP=${FETCHAPP%:*}
    APP_EXEC=${FETCHAPP#*:}

    case $APP in
        curl)
            APP_EXEC_ARG="${APP_EXEC} -s -${IPCLASS} --show-error"
            ;;
        fetch)
            APP_EXEC_ARG="${APP_EXEC}"
            ;;
        wget)
            APP_EXEC_ARG="${APP_EXEC} --quiet -O- http://ifconfig.me"
            ;;
    esac

    if [ ! -z "${INTERFACE}" ]; then
        APP_EXEC_ARG="${APP_EXEC_ARG} --interface ${INTERFACE}"
    fi

    APP_EXEC_ARG="${APP_EXEC_ARG} http://ifconfig.me"

    echoverbose "Fetch App found: ${APP}: ${APP_EXEC_ARG}"
}

# Verify that INTERFACE exists on the system.  Uses `ip` on Linux or
# `ifconfig` on BSD/macOS to enumerate available interfaces.
checkinterface() {
    if [ ! -z "${IP_CMD}" ] && [ -x "${IP_CMD}" ]; then
        INTERFACES=$($IP_CMD_EXEC | awk -F': ' '{print $2}')
    elif [ ! -z "${IFCONFIG_CMD}" ] && [ -x "${IFCONFIG_CMD}" ]; then
        INTERFACES=$($IFCONFIG_CMD_EXEC)
    else
        echoerr "Could not find ${IP_CMD} or ${IFCONFIG_CMD}; ensure the correct directories are in PATH"
    fi

    INTERFACE_FOUND=false
    echoverbose "Check if interface ${INTERFACE} in INTERFACES:" $INTERFACES
    for I in $INTERFACES; do
        [ "$INTERFACE" == "$I" ] && INTERFACE_FOUND=true && break
    done

    if [ "$INTERFACE_FOUND" == false ]; then
        echoerr "Could not find INTERFACE '${INTERFACE}'; valid interfaces are: ${INTERFACES}"
    fi
}

# Validate an IP address against a regex for the given address family.
#   $1 - IP address string
#   $2 - Address family: 4 or 6
# Returns 1 (true) if valid, 0 (false) if invalid.
# NOTE: return values are inverted from shell convention for historical reasons;
# callers use [ $? -eq 1 ] to test success.
checkipaddress() {
    local check_ip=$1
    local check_class=$2

    echoverbose "Checking if valid IP address ${check_ip} IPv${check_class}"

    if [ "$check_class" == 4 ]; then
        regex='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
    else
        regex='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
    fi

    if [[ $check_ip =~ $regex ]]; then
        return 1
    else
        echo "IP address ${check_ip} is not a valid IPv${check_class} address"
        return 0
    fi
}

# Query the nameserver for an existing resource record.
#   $1 - Hostname to look up
#   $2 - Nameserver IP
#   $3 - Record type (A, AAAA, CNAME, PTR)
# Sets the global RR_IP to the current record value (empty if none).
# Returns 0 if the record exists, 1 if it does not.
rrcheckname() {
    local rr_hostname=$1
    local rr_server=$2
    local rr_type=$3

    echoverbose "Run: dig -4 +short ${rr_hostname} ${rr_type} @${rr_server}"

    RR_IP=$(dig -4 +short "${rr_hostname}" "${rr_type}" "@${rr_server}")
    if [ $? != 0 ]; then
        echoverbose "Something went wrong with dig"
        echoverbose "dig returned '${RR_IP}'"
        exit 1
    fi

    # No record found
    [ -z "${RR_IP}" ] && return 0

    # CNAME and PTR responses are hostnames with a trailing dot — strip it
    # and return whether the record exists.
    if [ "${rr_type}" == "CNAME" ] || [ "${rr_type}" == "PTR" ]; then
        RR_IP=${RR_IP%?}
        if [ ! -z "${RR_IP}" ]; then
            echoverbose "Hostname ${rr_hostname} exists (RR_IP=${RR_IP})"
            return 0
        else
            echoverbose "Hostname ${rr_hostname} does not exist"
            return 1
        fi
    fi

    # A/AAAA — validate the returned IP
    checkipaddress "${RR_IP}" "${IPCLASS}"
    if [ $? -eq 1 ]; then
        echoverbose "Hostname ${rr_hostname} exists"
        return 0
    else
        echoverbose "Hostname ${rr_hostname} does not exist"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# IPv6 helper functions
# Source: https://stackoverflow.com/questions/14697403 (@user48678)
# ---------------------------------------------------------------------------

# Convert a hexadecimal string to its decimal representation.
hex2dec() {
    [ "$1" != "" ] && printf "%d" "$(( 0x$1 ))"
}

# Expand a possibly abbreviated IPv6 address into its full 8-group form.
expand_ipv6() {
    local ip=$1

    # Prepend 0 if the address starts with ':'
    echo "$ip" | grep -qs "^:" && ip="0${ip}"

    # Expand '::' into the appropriate number of zero groups
    if echo "$ip" | grep -qs "::"; then
        colons=$(echo "$ip" | sed 's/[^:]//g')
        missing=$(echo ":::::::::" | sed "s/$colons//")
        expanded=$(echo "$missing" | sed 's/:/:0/g')
        ip=$(echo "$ip" | sed "s/::/$expanded/")
    fi

    blocks=$(echo "$ip" | grep -o "[0-9a-f]\+")
    set $blocks

    printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" \
        $(hex2dec $1) \
        $(hex2dec $2) \
        $(hex2dec $3) \
        $(hex2dec $4) \
        $(hex2dec $5) \
        $(hex2dec $6) \
        $(hex2dec $7) \
        $(hex2dec $8)
}

# Convert an IPv6 address to its reverse DNS (ip6.arpa) form.
# Sets the global REVERSE_IP variable.
reverseip6() {
    local ipv6
    ipv6=$(expand_ipv6 "$1")
    REVERSE_IP=$(echo "$ipv6" | awk '{
        gsub(/:/,"")
        for (i=length($0); i>0; i--) {
            printf "%s.", substr($0,i,1)
        }
        print "ip6.arpa"
    }')
    echoverbose "REVERSE_IP = ${REVERSE_IP}"
}

# Convert an IPv4 address to its reverse DNS (in-addr.arpa) form.
# Sets the global REVERSE_IP variable.
reverseip4() {
    local forward_ip=$1
    [ -z "$forward_ip" ] && echoerr "reverseip4 called without an argument!"
    REVERSE_IP=$(echo "${forward_ip}" | awk 'BEGIN{FS="."}{print $4"."$3"."$2"."$1".in-addr.arpa"}')
}

# ---------------------------------------------------------------------------
# nsupdate payload generators
# ---------------------------------------------------------------------------

# Build an nsupdate payload that deletes a resource record.
makeNSUPDATE_DELETE() {
read -r -d '' NSUPDATE <<EOF
server ${NAMESERVER}
update delete ${HOSTNAME}.  ${RRTYPE}
show
send
quit
EOF
}

# Build an nsupdate payload that replaces (delete + add) a resource record.
makeNSUPDATE() {
read -r -d '' NSUPDATE <<EOF
server ${NAMESERVER}
update delete ${HOSTNAME}.  ${RRTYPE}
update add ${HOSTNAME}.     300      IN     ${RRTYPE} ${MY_IP}
show
send
quit
EOF
}

# ---------------------------------------------------------------------------
# Usage text
# ---------------------------------------------------------------------------

read -r -d '' usage <<EOF

usage: ${script_name} [-h HOSTNAME] [-k keyfile] [-c TARGET] [-6] [-4]
       [-I INTERFACE] [-n NAMESERVER] [-F] [-v] [-D] [-r] [-l logfile]
       [-H] [IP ADDRESS]

Dynamic DNS update client. Updates A, AAAA, CNAME or PTR records on a
BIND-compatible nameserver via nsupdate with TSIG key authentication.

If no IP ADDRESS is given on the command line, the script queries
http://ifconfig.me for the external address. Use -I to bind to a
specific network interface for that lookup.

Options:
    -h HOSTNAME    Hostname to set the resource record for
    -k KEYFILE     Path to the BIND TSIG key file
    -c TARGET      Create a CNAME record pointing to TARGET
                   (cannot combine with -r or a positional IP address)
    -6             Use IPv6 (AAAA record; applies to -I lookups)
    -4             Use IPv4 (A record; default)
    -I INTERFACE   Network interface for external IP lookup
    -n NAMESERVER  IP address of the authoritative nameserver
    -F             Force update even if the record already matches
    -v             Verbose output
    -D             Delete the resource record (if it exists)
    -r             Create a reverse (PTR) record for the IP address
    -l LOGFILE     Redirect all output (including STDERR) to LOGFILE
    -H             Show this help message
EOF

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

OPTSTRING=":l:c:h:I:n:k:H46vFDr"
IPCLASS=4
FORCE_UPDATE=0
DELETE=0
REVERSE=0
CNAME_TARGET=""

while getopts ${OPTSTRING} opt; do
    case ${opt} in
        h) HOSTNAME=${OPTARG} ;;
        c) CNAME_TARGET=${OPTARG} ;;
        4) IPCLASS=4 ;;
        6) IPCLASS=6 ;;
        I) INTERFACE=${OPTARG} ;;
        n) NAMESERVER=${OPTARG} ;;
        F) FORCE_UPDATE=1 ;;
        v) VERBOSE=1 ;;
        D) DELETE=1 ;;
        r) REVERSE=1 ;;
        l) LOGFILE=${OPTARG} ;;
        k) KEYFILE=${OPTARG} ;;
        H) echo "Help ${usage}"; exit 1 ;;
        :) echoerr_usage "Option -${OPTARG} requires an argument." ;;
        *) echoerr_usage "Unknown option -${OPTARG}" ;;
    esac
done

if [ $OPTIND == 1 ]; then
    echoerr_usage "${script_name} requires arguments"
fi

# Collect any positional IP address argument
shift $(($OPTIND - 1))
SETIP="$*"

# --- CNAME validation: mutually exclusive with -r and positional IP ---------
if [ ! -z "${CNAME_TARGET}" ]; then
    [ ${REVERSE} == 1 ] && echoerr_usage "-c (CNAME) cannot be combined with -r (reverse)"
    [ ! -z "$SETIP" ] && echoerr_usage "-c (CNAME) cannot be combined with a positional IP address"
    # Ensure the CNAME target is a FQDN (append trailing dot if missing)
    [[ "${CNAME_TARGET}" != *. ]] && CNAME_TARGET="${CNAME_TARGET}."
fi

# Validate positional IP address if provided
if [ ! -z "$SETIP" ]; then
    checkipaddress "${SETIP}" "${IPCLASS}"
    [ $? -eq 0 ] && echoerr_usage "IP ${SETIP} is not a valid IPv${IPCLASS} address"
fi

# --- Logging setup ----------------------------------------------------------
if [ ! -z "$LOGFILE" ]; then
    exec >> "${LOGFILE}" 2>&1
    [ $? != 0 ] && echoerr "Failed to open logfile: ${LOGFILE}"
    echo "$(date)"
fi

# --- Mandatory arguments ----------------------------------------------------
[ -z "${HOSTNAME}" ]   && echoerr_usage "HOSTNAME is empty"
[ -z "${NAMESERVER}" ] && echoerr_usage "NAMESERVER is empty"
[ -z "${KEYFILE}" ]    && echoerr_usage "KEYFILE is empty"

# Determine the DNS record type
if [ ! -z "${CNAME_TARGET}" ]; then
    RRTYPE=CNAME
elif [ "$IPCLASS" == 4 ]; then
    RRTYPE=A
else
    RRTYPE=AAAA
fi

# --- Optional interface check -----------------------------------------------
[ -z "${INTERFACE}" ] && echoverbose "INTERFACE is empty"

if [ "$IPCLASS" -ne 4 ] && [ "$IPCLASS" -ne 6 ]; then
    echoerr_usage "-6 or -4 is missing"
fi

if [ ! -z "${INTERFACE}" ]; then
    checkinterface
fi

# --- Key file check ---------------------------------------------------------
[ ! -r "$KEYFILE" ] && echoerr "KEYFILE ${KEYFILE} does not exist or is not readable."

# --- Nameserver address validation ------------------------------------------
checkipaddress "$NAMESERVER" 4
[ $? -eq 0 ] && echoerr_usage "NAMESERVER ${NAMESERVER} is not a valid IPv4 address"

# --- Determine the IP / CNAME target to use ---------------------------------
if [ ! -z "${CNAME_TARGET}" ]; then
    # CNAME mode: target is already set, no IP fetching needed
    MY_IP="${CNAME_TARGET}"
elif [ ! -z "${SETIP}" ]; then
    # Explicit IP provided on command line
    MY_IP="${SETIP}"
else
    # Fetch external IP from http://ifconfig.me
    getfetchapp
    echoverbose "run: ${APP_EXEC_ARG}"
    MY_IP=$(${APP_EXEC_ARG})
    [ $? != 0 ] && echoerr "${APP_EXEC_ARG} exited with non-zero exit code."
    checkipaddress "${MY_IP}" "${IPCLASS}"
    [ $? -eq 0 ] && echoerr "${MY_IP} is invalid, exiting..."
fi

# --- Reverse (PTR) record handling ------------------------------------------
if [ ${REVERSE} == 1 ]; then
    if [ "$IPCLASS" == 4 ]; then
        reverseip4 "$MY_IP"
    else
        reverseip6 "$MY_IP"
    fi

    # Swap: the hostname becomes the RDATA, the reverse IP becomes the owner
    MY_IP="${HOSTNAME}"
    HOSTNAME="${REVERSE_IP}"
    RRTYPE=PTR
fi

# --- Check if the resource record already exists ----------------------------
rrcheckname "${HOSTNAME}" "${NAMESERVER}" "${RRTYPE}"
echoverbose "Current state: MY_IP=${MY_IP} RR_IP=${RR_IP}"

# --- Decide what action to take ---------------------------------------------
if [ -z "${RR_IP}" ] && [ ${DELETE} == 1 ] && [ ${FORCE_UPDATE} == 0 ]; then
    echo "Nothing to delete on ${NAMESERVER}; ${HOSTNAME} does not exist."
    exit 0
elif [ "${RR_IP}" == "${MY_IP}" ] && [ ${FORCE_UPDATE} == 0 ] && [ ${DELETE} == 0 ]; then
    echo "Record unchanged for ${HOSTNAME} -> ${MY_IP}. Exiting."
    exit 0
elif [ ${DELETE} == 1 ]; then
    makeNSUPDATE_DELETE
else
    makeNSUPDATE
fi

# --- Execute nsupdate -------------------------------------------------------
echoverbose "Run NSUPDATE"
echoverbose "${NSUPDATE}"
echoverbose ""

NSUPDATE_RETURN=$(echo "${NSUPDATE}" | ${NSUPDATE_APP} -k "${KEYFILE}" -v)
if [ $? != 0 ]; then
    echo "Something went wrong with nsupdate:"
    echo "VERBOSE LOG -- ${ERROR_TXT}"
    echo "NSUPDATE LOG -- ${NSUPDATE_RETURN}"
    exit 1
fi

echoverbose ""
echoverbose "${NSUPDATE_RETURN}"

# --- Report result ----------------------------------------------------------
if [ ${DELETE} == 1 ]; then
    echo "Delete successful: ${HOSTNAME} -> ${MY_IP}"
else
    echo "Update successful: ${HOSTNAME} -> ${MY_IP}"
fi
