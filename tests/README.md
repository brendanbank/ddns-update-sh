# Tests

Offline test suite for `ddns-update.sh`. All tests run locally without a DNS
server or valid TSIG key.

## Running

```bash
./tests/run_tests.sh
```

## What is tested

| Category                  | Description                                           |
|---------------------------|-------------------------------------------------------|
| `checkipaddress`          | IPv4 and IPv6 address validation                      |
| `hex2dec`                 | Hex-to-decimal conversion helper                      |
| `expand_ipv6`             | Abbreviated IPv6 expansion to full 8-group form       |
| `reverseip4`              | IPv4 to `in-addr.arpa` conversion                     |
| `reverseip6`              | IPv6 to `ip6.arpa` conversion                         |
| Option parsing            | Missing required arguments produce correct errors     |
| CNAME mutual exclusivity  | `-c` rejects `-r` and positional IP combinations      |
| Nameserver validation     | Invalid nameserver IP is rejected                     |
| Help flag                 | `-H` displays usage including CNAME documentation     |
