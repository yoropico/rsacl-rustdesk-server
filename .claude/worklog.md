2026-11-26 17:14 | [coder] self hbbs-secure-tcp
2026-11-26 17:20 | [decision] hbbs-secure-tcp: base rsacl on tag 1.1.16 (what rd.rsautomation.co.kr runs), not upstream master (25 commits ahead incl. hbb_common bump) -- the swap must change only the key exchange
2026-11-26 17:20 | [decision] hbbs-secure-tcp: key exchange version 0 (legacy, no signed params) -- this hbb_common has no KxParams/version fields and 1.5.3 picks v0 against a server that advertises none
2026-11-26 17:20 | [decision] hbbs-secure-tcp: always offer on accept, decide by client's first frame -- clients since 1.2 skip a stray KeyExchange (get_next_nonkeyexchange_msg), as with RustDesk Server Pro
2026-11-26 17:30 | [decision] hbbs-secure-tcp: package built on GitHub Actions (rsacl.yaml) with upstream's exact musl/cross/debuild steps instead of a local cross build -- same layout as the official deb, verified file-by-file
