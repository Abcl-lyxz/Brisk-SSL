# Handoff - 2026-09-22 (session 11)

## Done
- d2e2459 **x509: RFC 9525 hostname / IP matching. M2 line 4 closed.** New `src/x509/name.c`
  (952 B armv7hf .. 2040 B mips64, RAM unchanged): `brisk__x509_match_host` walks the SAN
  entries `cert.c` leaves encoded - dNSName [2] for a DNS-ID, iPAddress [7] octet-for-octet for
  an IP-ID - and `brisk__x509_parse_ip` is the single classifier that decides which. 120 new
  vectors (71 name rows + 49 IP literals) and `fuzz/fuzz_name.c` (`python tools/dev.py fuzz
  name`, 20.5M runs clean). 11 archs + asan, TINY, ct green, baseline re-saved.

## In progress
- Nothing. The tree is clean.

## Next up
- M2 line 5: `Time policy STRICT / FLOOR (default) / INSECURE_NO_TIME; int64 dates`.
  `brisk__x509_time` and `not_before` / `not_after` already exist and are tested
  (`tests/kat/x509_time.inc`, 41 rows); nothing compares them against a clock yet. Expect the
  knob in `include/brisk_config.h` and the comparison at the same layer as
  `brisk__x509_chain_verify`, which today documents the validity window as explicitly NOT its
  job (see the chain.c block in `src/brisk_int.h`).

## Decisions / gotchas
- **Both reviewers keep earning their keep - run `rfc-auditor` AND `portability-reviewer` on
  every x509 change.** Portability found nothing this round (it fuzzed `parse_ip` against
  Python's `ipaddress` and ran `match_host` against guard pages); `rfc-auditor` found the real
  bug below plus a test gap no vector could have shown.
- **A reference identifier that is not an IP is not therefore a name.** `010.0.0.1`, `127.1`,
  `2130706433`, `0x7f.0.0.1` are all refused by `parse_ip` and were then accepted as DNS-IDs,
  while the OS resolver turns every one into an address - the split classification RFC 9525 7.4
  is a whole section about. `numeric_tld()` now rejects an all-digit right-most label
  (RFC 1123 2.1). Any future "is this a host name?" check owes the same guard.
- **"MUST be ignored" is a claim about what happens NEXT.** Every bad-SAN-entry vector had the
  bad entry ALONE, so `BRISK_E_AUTH` could not tell "ignored it and kept searching" from
  "aborted the whole search". The rows that pin it down put a junk dNSName BEFORE the good one.
  Same trap applies to any future per-entry rule.
- **This Bash tool's heredoc eats backslashes.** `<<'EOF'` still collapsed `\\x00` to a real NUL
  and wrote it into tools/kat.py. Patch scripts with escapes in them go through the Write tool,
  or build the bytes with `bytes([92])`.
- Do not write .c fragments into the scratchpad: the post-edit hook formats them with default
  clang-format (2-space, reflowed comments) and that style then travels into the repo file.
- **M8 amalgamation hazard, pre-existing:** `src/crypto/aes_ct.c` and `aes_ct64.c` both define
  static `ortho`, `bswap32`, `sbox`, `sub_word`, `skey_expand`, `add_round_key`, `mix_columns`,
  `shift_rows`. Two of those files in one TU will not link. (`name.c`'s seven statics were
  checked against the whole tree and collide with nothing.)
