# rsacl-rustdesk-server -- SPEC

Fork of `rustdesk/rustdesk-server` run as RS's RustDesk ID server (`rd.rsautomation.co.kr`,
hbbs + hbbr, shared with outside dealers). Branch `rsacl` = upstream tag `1.1.16` plus the
changes below; `master` mirrors upstream. Only hbbs differs; hbbr is upstream's.

## Rendezvous key exchange on TCP 21116 (module `src/secure_tcp.rs`)

Interface: `secure_tcp::offer(&server_sk) -> (RendezvousMessage, Offer)`,
`Offer::first_frame(&bytes) -> Secured(Encrypt) | Plain | Err`, `seal`, `open`.

- On every accepted TCP connection of the main port (not websocket, not the NAT-test port),
  when hbbs holds a signing key (`-k _` / `id_ed25519`), hbbs sends first, in clear:
  `KeyExchange { keys: [sign(ephemeral_x25519_pk, server_ed25519_sk)] }` (version 0: no
  `version`, no signed params; the X25519 pk high bit is always clear).
- The client's FIRST frame decides the connection:
  - `KeyExchange { keys: [client_x25519_pk, box_seal(symmetric_key)] }` -> hbbs opens the key
    (`Encrypt::decode`) and from then on every frame both ways is `secretbox`-sealed with it,
    nonce = per-direction counter starting at 1 (hbb_common `Encrypt`). The answer frame
    itself carries no request.
  - anything else -> a plain request (logged-out client, old client); handled as before, the
    connection stays unencrypted for its life.
  - a `KeyExchange` that cannot be opened (wrong key count, bad box) -> that connection closes.
- The send-side state lives in the `Sink::TcpStream` stored in `tcp_punch`, so a reply sent
  later from another connection's task (PunchHoleResponse, RelayResponse, LocalAddr answer)
  is sealed for its connection.
- A frame that fails to decrypt closes the connection.
- Clients that never answer skip the offer when reading (`get_next_nonkeyexchange_msg`,
  RustDesk >= 1.2); a pre-1.2 client reads it as an unexpected message and retries.

Tests: `cargo test --lib secure_tcp` (both directions, wrong server key, plain first frame,
malformed answer); `cargo test --test secure_tcp` (real hbbs on loopback: logged-in client
secured with direct and stored-sink replies, peer answering secured and plain; logged-out
client; old client request-first; garbage answer closes only that connection).

## Package

`.github/workflows/rsacl.yaml` builds `x86_64-unknown-linux-musl` with cross + toolchain 1.90
and the debs with debuild from `debian/`, as upstream `build.yaml` does; version in
`debian/changelog` (`1.1.16+rsaclN`). The server swap is infra-cmdb's (`sys/RUSTDESK`).
