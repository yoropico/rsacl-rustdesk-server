//! Server side of the rendezvous key exchange on hbbs' TCP port (21116).
//!
//! RustDesk clients with a server key configured and a login token (or a switch code, or a
//! WebRTC offer to carry) call `secure_tcp` on their TCP connection to hbbs and wait for the
//! server to speak first with `RendezvousMessage::KeyExchange`. Upstream open-source hbbs never
//! sends one, so those clients time out ("Failed to secure tcp: deadline has elapsed").
//!
//! The exchange implemented here is the original scheme ("version 0", the legacy one every
//! client accepts):
//!
//! - server: `KeyExchange { keys: [sign(ephemeral_x25519_pk, server_ed25519_sk)] }`, in clear,
//!   as soon as the connection is accepted;
//! - client: `KeyExchange { keys: [client_x25519_pk, box_seal(symmetric_key)] }`, in clear;
//! - both: every later frame is `secretbox`-sealed with that one symmetric key, each direction
//!   with its own counter as the nonce (hbb_common `Encrypt`).
//!
//! The server decides by the client's first frame. A client that never answers the exchange (a
//! logged-out client, or an old one that sends its request first without waiting) gets the
//! connection unencrypted, exactly as before; clients skip the server's `KeyExchange` when they
//! read (`get_next_nonkeyexchange_msg`).

use hbb_common::{
    bail,
    bytes::BytesMut,
    protobuf::Message as _,
    rendezvous_proto::{rendezvous_message, KeyExchange, RendezvousMessage},
    tcp::Encrypt,
    ResultType,
};
use sodiumoxide::crypto::{box_, sign};

/// The server's half of an exchange that was offered on one connection and not yet answered.
pub struct Offer {
    our_sk: box_::SecretKey,
}

/// What the client's first frame on a connection with an open offer turned out to be.
pub enum FirstFrame {
    /// The client answered the exchange: encrypt the connection with this state from now on.
    /// The frame itself is consumed by the exchange and carries no request.
    Secured(Encrypt),
    /// Anything else: an unencrypted request from a client that did not take the offer. Handle
    /// the frame as a request and keep the connection unencrypted.
    Plain,
}

/// Build the server's opening `KeyExchange`, signed with the server key, and the offer that
/// opens the client's answer.
pub fn offer(server_sk: &sign::SecretKey) -> (RendezvousMessage, Offer) {
    let (our_pk, our_sk) = box_::gen_keypair();
    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange {
        keys: vec![sign::sign(&our_pk.0, server_sk).into()],
        ..Default::default()
    });
    (msg, Offer { our_sk })
}

impl Offer {
    /// Classify the client's first frame. An answer that is a `KeyExchange` but cannot be
    /// opened is an error: the client believes the connection is encrypted, so treating its
    /// next frames as plain would only misparse them.
    pub fn first_frame(self, bytes: &[u8]) -> ResultType<FirstFrame> {
        let Ok(msg) = RendezvousMessage::parse_from_bytes(bytes) else {
            return Ok(FirstFrame::Plain);
        };
        let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
            return Ok(FirstFrame::Plain);
        };
        if ex.keys.len() != 2 {
            bail!(
                "key exchange answer has {} keys, expected 2",
                ex.keys.len()
            );
        }
        let key = Encrypt::decode(&ex.keys[1], &ex.keys[0], &self.our_sk)?;
        Ok(FirstFrame::Secured(Encrypt::new(key)))
    }
}

/// Encrypt one outgoing frame when the connection is secured.
pub fn seal(enc: Option<&mut Encrypt>, bytes: Vec<u8>) -> Vec<u8> {
    match enc {
        Some(enc) => enc.enc(&bytes),
        None => bytes,
    }
}

/// Decrypt one incoming frame in place when the connection is secured.
pub fn open(dec: Option<&mut Encrypt>, bytes: &mut BytesMut) -> ResultType<()> {
    if let Some(dec) = dec {
        dec.dec(bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::secretbox;

    /// The client side as RustDesk 1.5.3 runs it against a version-0 server
    /// (`src/common.rs` `key_exchange` + `create_symmetric_key_msg`): verify the signed key,
    /// seal a fresh symmetric key to it, answer, and encrypt with that key.
    fn client_answer(
        server_msg: &RendezvousMessage,
        rs_pk: &sign::PublicKey,
    ) -> ResultType<(RendezvousMessage, Encrypt)> {
        let Some(rendezvous_message::Union::KeyExchange(ex)) = &server_msg.union else {
            bail!("not a key exchange");
        };
        if ex.keys.len() != 1 {
            bail!("invalid key exchange message");
        }
        let signed = sign::verify(&ex.keys[0], rs_pk)
            .map_err(|_| hbb_common::anyhow::anyhow!("Signature mismatch in key exchange"))?;
        let mut their_pk = [0u8; 32];
        if signed.len() != 32 {
            bail!("wrong public key length");
        }
        their_pk.copy_from_slice(&signed);
        // 1.5.3 treats a set high bit as a server that signs its parameters (version 1).
        if their_pk[31] & 0x80 != 0 {
            bail!("high bit set: the client would demand signed parameters");
        }
        let (our_pk, our_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(&key.0, &nonce, &box_::PublicKey(their_pk), &our_sk);
        let mut out = RendezvousMessage::new();
        out.set_key_exchange(KeyExchange {
            keys: vec![our_pk.0.to_vec().into(), sealed.into()],
            ..Default::default()
        });
        Ok((out, Encrypt::new(key)))
    }

    fn punch_request(id: &str) -> RendezvousMessage {
        let mut msg = RendezvousMessage::new();
        msg.set_punch_hole_request(hbb_common::rendezvous_proto::PunchHoleRequest {
            id: id.to_owned(),
            ..Default::default()
        });
        msg
    }

    #[test]
    fn exchange_both_ways() {
        let (rs_pk, rs_sk) = sign::gen_keypair();
        for _ in 0..64 {
            let (hello, offer) = offer(&rs_sk);
            let wire = hello.write_to_bytes().unwrap();
            let hello = RendezvousMessage::parse_from_bytes(&wire).unwrap();
            let (answer, mut client) = client_answer(&hello, &rs_pk).unwrap();
            let FirstFrame::Secured(server) =
                offer.first_frame(&answer.write_to_bytes().unwrap()).unwrap()
            else {
                panic!("answer not recognised");
            };
            let (mut server_rx, mut server_tx) = (server.clone(), server);

            // client -> server
            let req = punch_request("123456789").write_to_bytes().unwrap();
            let mut frame = BytesMut::from(&client.enc(&req)[..]);
            assert_ne!(&frame[..], &req[..]);
            open(Some(&mut server_rx), &mut frame).unwrap();
            assert_eq!(&frame[..], &req[..]);
            // a second frame advances the counter on both sides
            let mut frame = BytesMut::from(&client.enc(&req)[..]);
            open(Some(&mut server_rx), &mut frame).unwrap();
            assert_eq!(&frame[..], &req[..]);

            // server -> client
            let resp = punch_request("987654321").write_to_bytes().unwrap();
            for _ in 0..2 {
                let sealed = seal(Some(&mut server_tx), resp.clone());
                let mut frame = BytesMut::from(&sealed[..]);
                client.dec(&mut frame).unwrap();
                assert_eq!(&frame[..], &resp[..]);
            }
        }
    }

    #[test]
    fn wrong_server_key_is_refused_by_the_client() {
        let (_, rs_sk) = sign::gen_keypair();
        let (other_pk, _) = sign::gen_keypair();
        let (hello, _) = offer(&rs_sk);
        assert!(client_answer(&hello, &other_pk).is_err());
    }

    #[test]
    fn plain_request_first_stays_plain() {
        let (_, rs_sk) = sign::gen_keypair();
        let (_, offer) = offer(&rs_sk);
        let req = punch_request("123456789").write_to_bytes().unwrap();
        assert!(matches!(offer.first_frame(&req).unwrap(), FirstFrame::Plain));
        let (_, offer2) = super::offer(&rs_sk);
        assert!(matches!(
            offer2.first_frame(b"not protobuf \xff\xff").unwrap(),
            FirstFrame::Plain
        ));
        let mut bytes = BytesMut::from(&req[..]);
        open(None, &mut bytes).unwrap();
        assert_eq!(&bytes[..], &req[..]);
        assert_eq!(seal(None, req.clone()), req);
    }

    #[test]
    fn malformed_answer_is_an_error() {
        let (_, rs_sk) = sign::gen_keypair();
        let mut bad = RendezvousMessage::new();
        bad.set_key_exchange(KeyExchange {
            keys: vec![vec![1u8; 32].into()],
            ..Default::default()
        });
        let (_, o) = offer(&rs_sk);
        assert!(o.first_frame(&bad.write_to_bytes().unwrap()).is_err());
        bad.set_key_exchange(KeyExchange {
            keys: vec![vec![1u8; 32].into(), vec![2u8; 48].into()],
            ..Default::default()
        });
        let (_, o) = offer(&rs_sk);
        assert!(o.first_frame(&bad.write_to_bytes().unwrap()).is_err());
    }
}
