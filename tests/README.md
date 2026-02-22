# Tests

## Unit tests (`run_tests.sh`)

Offline test suite for `ddns-update.sh`. All tests run locally without a DNS
server or valid TSIG key.

```bash
./tests/run_tests.sh
```

### What is tested

| Category                  | Description                                           |
|---------------------------|-------------------------------------------------------|
| `checkipaddress`          | IPv4 and IPv6 address validation                      |
| `hex2dec`                 | Hex-to-decimal conversion helper                      |
| `expand_ipv6`             | Abbreviated IPv6 expansion to full 8-group form       |
| `reverseip4`              | IPv4 to `in-addr.arpa` conversion                     |
| `reverseip6`              | IPv6 to `ip6.arpa` conversion                         |
| Option parsing            | Missing required arguments produce correct errors     |
| Interface validation      | `-I` rejects invalid interfaces, accepts valid ones   |
| CNAME mutual exclusivity  | `-c` rejects `-r` and positional IP combinations      |
| Nameserver validation     | Invalid nameserver IP is rejected                     |
| Help flag                 | `-H` displays usage including CNAME documentation     |

## Live integration tests (`live_tests.sh`)

Performs real DNS updates against a live nameserver and verifies the results
with `dig`. Requires a config file with nameserver, key, and test domain.

```bash
cp tests/live_tests.conf.example tests/live_tests.conf
# Edit live_tests.conf with your values
./tests/live_tests.sh
```

### What is tested

| Category                  | Description                                           |
|---------------------------|-------------------------------------------------------|
| A record                  | Create, idempotency, update, force update, delete     |
| AAAA record               | Create, idempotency, update, force update, delete     |
| CNAME record              | Create and delete                                     |
| PTR record (IPv4)         | Create, idempotency, delete, recreate at new IP       |
| PTR record (IPv6)         | Create, idempotency, delete, recreate at new address  |
| `-I` interface (IPv4)     | Auto-detect external IPv4 via ifconfig.me             |
| `-I` interface (IPv6)     | Auto-detect external IPv6 via ifconfig.me             |

All records are cleaned up automatically before and after the test run.
