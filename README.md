# ddns-update.sh

A dynamic DNS update client for BIND-compatible nameservers. Updates A, AAAA,
CNAME and PTR records using `nsupdate` with TSIG key authentication.

When no IP address is provided on the command line, the script automatically
detects the external address via [ifconfig.me](http://ifconfig.me).

## Requirements

- `bash`
- `nsupdate` (part of [BIND](https://www.isc.org/bind/) or `bind-utils`)
- `dig` (part of BIND or `bind-utils`)
- `curl` (for external IP detection)
- A TSIG key file for authenticating DNS updates

## Installation

```bash
curl -O https://raw.githubusercontent.com/brendanbank/ddns-update-sh/master/ddns-update.sh
chmod +x ddns-update.sh
```

Or clone the repository:

```bash
git clone https://github.com/brendanbank/ddns-update-sh.git
cd ddns-update-sh
```

## Usage

```
usage: ddns-update.sh [-h HOSTNAME] [-k keyfile] [-c TARGET] [-6] [-4]
       [-I INTERFACE] [-n NAMESERVER] [-F] [-v] [-D] [-r] [-l logfile]
       [-H] [IP ADDRESS]
```

### Options

| Option          | Description                                                    |
|-----------------|----------------------------------------------------------------|
| `-h HOSTNAME`   | Hostname to set the resource record for                        |
| `-k KEYFILE`    | Path to the BIND TSIG key file                                 |
| `-c TARGET`     | Create a CNAME record pointing to TARGET                       |
| `-6`            | Use IPv6 (AAAA record)                                         |
| `-4`            | Use IPv4 (A record; default)                                   |
| `-I INTERFACE`  | Network interface for external IP lookup                       |
| `-n NAMESERVER` | IP address of the authoritative nameserver                     |
| `-F`            | Force update even if the record already matches                |
| `-v`            | Verbose output                                                 |
| `-D`            | Delete the resource record                                     |
| `-r`            | Create a reverse (PTR) record                                  |
| `-l LOGFILE`    | Redirect all output to a log file                              |
| `-H`            | Show help message                                              |

### Examples

**Update an A record** with auto-detected external IPv4:

```bash
./ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key.conf
```

**Update an AAAA record** on a specific interface:

```bash
./ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key.conf -6 -I eth0
```

**Set a specific IP address** (skip auto-detection):

```bash
./ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key.conf 203.0.113.42
```

**Create a CNAME record:**

```bash
./ddns-update.sh -h alias.example.com -c target.example.com -n 10.0.0.1 -k /path/to/key.conf
```

**Create a reverse PTR record:**

```bash
./ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key.conf -r 203.0.113.42
```

**Delete a record:**

```bash
./ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key.conf -D
```

**Force update** (even if the record hasn't changed):

```bash
./ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key.conf -F
```

## Configuration File (.env)

Instead of passing `-n` and `-k` on every invocation, you can create a `.env`
file in the same directory as the script:

```bash
NAMESERVER=10.0.0.1
KEYFILE=/path/to/key.conf
```

Any variable that corresponds to a command-line option can be set here (e.g.
`HOSTNAME`, `INTERFACE`, `IPCLASS`). Command-line arguments always override
`.env` values.

With a `.env` in place, the examples above simplify to:

```bash
./ddns-update.sh -h myhost.example.com
./ddns-update.sh -h myhost.example.com -6 -I eth0
./ddns-update.sh -h alias.example.com -c target.example.com
```

The `.env` file is gitignored by default to prevent accidental commits of
credentials.

## TSIG Key File

The key file is a standard BIND TSIG key in the format:

```
key "keyname" {
    algorithm hmac-sha512;
    secret "base64-encoded-secret";
};
```

Generate one with `tsig-keygen`:

```bash
tsig-keygen -a hmac-sha512 keyname > /path/to/key.conf
```

## Cron Example

Run every 5 minutes to keep a dynamic DNS record up to date:

```cron
*/5 * * * * /usr/local/bin/ddns-update.sh -h myhost.example.com -n 10.0.0.1 -k /path/to/key.conf -l /var/log/ddns-update.log
```

## Running Tests

### Unit tests

The unit test suite validates option parsing, IP validation, IPv6 expansion,
reverse-IP generation, and interface checking without requiring a live DNS
server:

```bash
./tests/run_tests.sh
```

### Live integration tests

The live test suite performs real DNS updates against a nameserver and verifies
the results with `dig`. It covers A, AAAA, CNAME, PTR (IPv4 and IPv6) records,
idempotency checks, force updates, deletes, and external IP auto-detection via
`-I INTERFACE`.

1. Copy the example config and fill in your values:

```bash
cp tests/live_tests.conf.example tests/live_tests.conf
```

2. Edit `tests/live_tests.conf` with your nameserver, TSIG key path, test
   domain, reverse delegation prefixes, and network interface:

```
LIVE_NAMESERVER="10.0.0.1"
LIVE_KEYFILE="/path/to/tsig.key"
LIVE_DOMAIN="test.example.com"
LIVE_PTR_NET="10.99.99"
LIVE_PTR6_PREFIX="2001:db8:1:2:3:4"
LIVE_INTERFACE="en0"
```

3. Run the tests:

```bash
./tests/live_tests.sh
```

The config file (`*.conf`) is gitignored and will not be committed.

See [tests/README.md](tests/README.md) for details.

## License

BSD 2-Clause "Simplified" License. See [LICENSE](LICENSE) for the full text.
