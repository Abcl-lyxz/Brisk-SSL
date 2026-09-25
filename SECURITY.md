# Security policy

## Supported versions
| Version | Supported |
|---|---|
| 0.1.x | yes - fixes land on `main` and in the next 0.1.x release |
| older | no |

v0.1.0 is the first release: well tested (official vectors, 10 architectures, fuzzing, a
constant-time check, interop against real servers), but not independently audited yet. Weigh
that before protecting high-value traffic with it.

## Reporting a vulnerability
Please report privately through GitHub: **Security → Report a vulnerability** on
https://github.com/Abcl-lyxz/Brisk-SSL (private vulnerability reporting). Do not open a public
issue for security problems. Include the affected version or commit, target architecture, and a
reproducer if possible. You will get an acknowledgement within 7 days.

## Scope
In scope: memory-safety bugs, cryptographic or constant-time flaws, certificate-validation
bypasses, protocol state-machine or downgrade issues, insecure defaults.

Known limits, by design (see docs/ARCHITECTURE.md): no certificate revocation checking
(CRL / OCSP), no 0-RTT, P-384 and RSA are verify-only, and GHASH timing on CPUs with
early-terminating multipliers (armv5, some MIPS32) is covered by the multiply-free GHASH that
those targets select automatically.
