//! Runs the built hbbs on loopback and talks to its TCP port (21116 role) the three ways
//! clients do:
//!
//! - a logged-in RustDesk 1.5.3 (`secure_tcp`): waits for the server's `KeyExchange`, answers,
//!   and sends its request encrypted;
//! - a logged-out client: sends its request first and skips the server's `KeyExchange` when it
//!   reads (`get_next_nonkeyexchange_msg`);
//! - an old client: sends its request first and reads raw frames.
//!
//! The answer comes once straight back on the request's own connection (unknown id), and once
//! through the sink hbbs keeps in `tcp_punch` and fills later from the peer's own TCP connection
//! (`LocalAddr` for a peer on the same host), so both paths are covered encrypted and plain.

use hbb_common::{
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    futures::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::Encrypt,
    tokio::{
        self,
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout, Duration},
    },
    tokio_util::codec::Framed,
    AddrMangle,
};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

const WAIT: Duration = Duration::from_secs(5);

struct Hbbs {
    child: Child,
    port: u16,
    pk: sign::PublicKey,
    dir: PathBuf,
}

impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        } else {
            eprintln!("hbbs log kept in {}", self.dir.display());
        }
    }
}

async fn start_hbbs() -> Hbbs {
    sodiumoxide::init().unwrap();
    // hbbs binds port, port-1 (NAT test) and port+2 (websocket) with SO_REUSEPORT, so two
    // instances on overlapping ports would both bind and steal each other's connections. Each
    // test takes its own block of four ports, spread by process id, and checks it is free.
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let base = 20_000 + (std::process::id() % 1_000) as u16 * 40;
    let port = loop {
        let p = base + 1 + NEXT.fetch_add(4, std::sync::atomic::Ordering::SeqCst);
        if std::net::TcpListener::bind(("0.0.0.0", p - 1)).is_ok()
            && std::net::TcpListener::bind(("0.0.0.0", p)).is_ok()
            && std::net::TcpListener::bind(("0.0.0.0", p + 2)).is_ok()
            && std::net::UdpSocket::bind(("0.0.0.0", p)).is_ok()
        {
            break p;
        }
    };
    let dir = std::env::temp_dir().join(format!("hbbs-kx-test-{}-{}", std::process::id(), port));
    std::fs::create_dir_all(&dir).unwrap();
    let (pk, sk) = sign::gen_keypair();
    std::fs::write(dir.join("id_ed25519"), base64::encode(sk.0)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .args(["-p", &port.to_string(), "-k", "_"])
        .current_dir(&dir)
        .env("RUST_LOG", "debug")
        .stdout(Stdio::from(std::fs::File::create(dir.join("hbbs.log")).unwrap()))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let hbbs = Hbbs {
        child,
        port,
        pk,
        dir,
    };
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return hbbs;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs did not start listening on {port}");
}

/// A TCP connection to hbbs framed and (once exchanged) encrypted the way the client's
/// `FramedStream` does it.
struct Conn {
    framed: Framed<TcpStream, BytesCodec>,
    enc: Option<Encrypt>,
}

impl Conn {
    async fn connect(port: u16) -> Conn {
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        Conn {
            framed: Framed::new(s, BytesCodec::new()),
            enc: None,
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.framed.get_ref().local_addr().unwrap()
    }

    async fn send(&mut self, msg: &RendezvousMessage) {
        let mut bytes = msg.write_to_bytes().unwrap();
        if let Some(enc) = self.enc.as_mut() {
            bytes = enc.enc(&bytes);
        }
        self.framed.send(Bytes::from(bytes)).await.unwrap();
    }

    async fn next_raw(&mut self) -> Option<BytesMut> {
        match timeout(WAIT, self.framed.next()).await {
            Ok(Some(Ok(mut bytes))) => {
                if let Some(enc) = self.enc.as_mut() {
                    enc.dec(&mut bytes).unwrap();
                }
                Some(bytes)
            }
            other => {
                eprintln!("next_raw: {:?}", other.map(|o| o.map(|r| r.map(|b| b.len()))));
                None
            }
        }
    }

    async fn next(&mut self) -> RendezvousMessage {
        let bytes = self.next_raw().await.expect("no frame from hbbs");
        RendezvousMessage::parse_from_bytes(&bytes).expect("frame does not parse")
    }

    /// `get_next_nonkeyexchange_msg` of the client.
    async fn next_nonkeyexchange(&mut self) -> RendezvousMessage {
        for _ in 0..2 {
            let msg = self.next().await;
            if !matches!(msg.union, Some(rendezvous_message::Union::KeyExchange(_))) {
                return msg;
            }
        }
        panic!("only key exchanges from hbbs");
    }

    /// `key_exchange` of RustDesk 1.5.3 (`src/common.rs`) against a version-0 server.
    async fn secure(&mut self, rs_pk: &sign::PublicKey) {
        let msg = self.next().await;
        let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
            panic!("hbbs did not open with a key exchange: {msg:?}");
        };
        assert_eq!(ex.keys.len(), 1);
        let their_pk = sign::verify(&ex.keys[0], rs_pk).expect("signature mismatch");
        let their_pk: [u8; 32] = their_pk.try_into().expect("wrong pk length");
        assert_eq!(their_pk[31] & 0x80, 0, "client would demand signed params");
        let (our_pk, our_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(&key.0, &nonce, &box_::PublicKey(their_pk), &our_sk);
        let mut out = RendezvousMessage::new();
        out.set_key_exchange(KeyExchange {
            keys: vec![our_pk.0.to_vec().into(), sealed.into()],
            ..Default::default()
        });
        self.send(&out).await;
        self.enc = Some(Encrypt::new(key));
    }
}

fn licence(hbbs: &Hbbs) -> String {
    base64::encode(hbbs.pk.0)
}

fn punch_request(hbbs: &Hbbs, id: &str, token: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        token: token.to_owned(),
        licence_key: licence(hbbs),
        version: "1.5.3".to_owned(),
        ..Default::default()
    });
    msg
}

fn punch_failure(msg: &RendezvousMessage) -> Option<punch_hole_response::Failure> {
    match &msg.union {
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => r.failure.enum_value().ok(),
        _ => None,
    }
}

/// A peer registered over UDP that answers hbbs' `FetchLocalAddr` from its own TCP
/// connection, secured or not, the way a controlled RustDesk does for a peer on its LAN.
struct Peer {
    udp: UdpSocket,
    id: String,
}

impl Peer {
    async fn register(hbbs: &Hbbs, id: &str) -> Peer {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(("127.0.0.1", hbbs.port)).await.unwrap();
        let roundtrip = |msg: RendezvousMessage| {
            let udp = &udp;
            async move {
                udp.send(&msg.write_to_bytes().unwrap()).await.unwrap();
                let mut buf = [0u8; 2048];
                let n = timeout(WAIT, udp.recv(&mut buf)).await.unwrap().unwrap();
                RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap()
            }
        };
        let mut reg = RendezvousMessage::new();
        reg.set_register_peer(RegisterPeer {
            id: id.to_owned(),
            serial: 0,
            ..Default::default()
        });
        // unknown peer: hbbs asks for its key first, as for a fresh RustDesk install
        let resp = roundtrip(reg.clone()).await;
        let Some(rendezvous_message::Union::RegisterPeerResponse(r)) = resp.union else {
            panic!("{resp:?}");
        };
        assert!(r.request_pk);
        let mut rk = RendezvousMessage::new();
        rk.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: id.as_bytes().to_vec().into(),
            pk: box_::gen_keypair().0 .0.to_vec().into(),
            ..Default::default()
        });
        let resp = roundtrip(rk).await;
        assert!(
            matches!(resp.union, Some(rendezvous_message::Union::RegisterPkResponse(ref r))
                if r.result.enum_value().ok() == Some(register_pk_response::Result::OK)),
            "{resp:?}"
        );
        let resp = roundtrip(reg).await;
        let Some(rendezvous_message::Union::RegisterPeerResponse(r)) = resp.union else {
            panic!("{resp:?}");
        };
        assert!(!r.request_pk);
        Peer {
            udp,
            id: id.to_owned(),
        }
    }

    async fn answer_fetch_local_addr(&self, hbbs: &Hbbs, secured: bool) {
        let mut buf = [0u8; 2048];
        let n = timeout(WAIT, self.udp.recv(&mut buf)).await.unwrap().unwrap();
        let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
        let Some(rendezvous_message::Union::FetchLocalAddr(fla)) = msg.union else {
            panic!("peer expected FetchLocalAddr, got {msg:?}");
        };
        let mut conn = Conn::connect(hbbs.port).await;
        if secured {
            conn.secure(&hbbs.pk).await;
        }
        let mut out = RendezvousMessage::new();
        out.set_local_addr(LocalAddr {
            socket_addr: fla.socket_addr,
            local_addr: AddrMangle::encode(conn.local_addr()).into(),
            relay_server: fla.relay_server,
            id: self.id.clone(),
            version: "1.5.3".to_owned(),
            ..Default::default()
        });
        conn.send(&out).await;
        // keep the connection open long enough for hbbs to read it
        sleep(Duration::from_millis(300)).await;
    }
}

fn run<F: std::future::Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f);
}

#[test]
fn logged_in_client_is_secured_and_answered_encrypted() {
    run(async {
        let hbbs = start_hbbs().await;
        // straight answer on the same connection
        let mut c = Conn::connect(hbbs.port).await;
        c.secure(&hbbs.pk).await;
        c.send(&punch_request(&hbbs, "nobody", "access-token")).await;
        let resp = c.next().await;
        assert_eq!(
            punch_failure(&resp),
            Some(punch_hole_response::Failure::ID_NOT_EXIST)
        );

        // later answer through the stored sink, the peer secured and plain
        for peer_secured in [true, false] {
            let peer = Peer::register(&hbbs, &format!("peer-in-{peer_secured}")).await;
            let mut c = Conn::connect(hbbs.port).await;
            c.secure(&hbbs.pk).await;
            c.send(&punch_request(&hbbs, &peer.id, "access-token")).await;
            peer.answer_fetch_local_addr(&hbbs, peer_secured).await;
            let resp = c.next().await;
            let Some(rendezvous_message::Union::PunchHoleResponse(r)) = resp.union else {
                panic!("expected PunchHoleResponse, got {resp:?}");
            };
            assert!(r.is_local(), "{r:?}");
            assert!(!r.socket_addr.is_empty(), "{r:?}");
        }
    });
}

#[test]
fn logged_out_client_stays_plain() {
    run(async {
        let hbbs = start_hbbs().await;
        let mut c = Conn::connect(hbbs.port).await;
        c.send(&punch_request(&hbbs, "nobody", "")).await;
        let resp = c.next_nonkeyexchange().await;
        assert_eq!(
            punch_failure(&resp),
            Some(punch_hole_response::Failure::ID_NOT_EXIST)
        );

        let peer = Peer::register(&hbbs, "peer-out").await;
        let mut c = Conn::connect(hbbs.port).await;
        c.send(&punch_request(&hbbs, &peer.id, "")).await;
        peer.answer_fetch_local_addr(&hbbs, false).await;
        let resp = c.next_nonkeyexchange().await;
        assert!(matches!(
            resp.union,
            Some(rendezvous_message::Union::PunchHoleResponse(ref r)) if r.is_local()
        ));
    });
}

#[test]
fn old_client_request_first_reads_offer_then_plain_answer() {
    run(async {
        let hbbs = start_hbbs().await;
        let mut c = Conn::connect(hbbs.port).await;
        // no wait at all: the request may cross the server's offer on the wire
        c.send(&punch_request(&hbbs, "nobody", "")).await;
        let first = c.next().await;
        assert!(
            matches!(first.union, Some(rendezvous_message::Union::KeyExchange(_))),
            "{first:?}"
        );
        let second = c.next().await;
        assert_eq!(
            punch_failure(&second),
            Some(punch_hole_response::Failure::ID_NOT_EXIST)
        );
        // nothing else follows in clear or otherwise: upstream hbbs hands the sink to the
        // answer and the connection carries no more replies, as before this change
        assert!(c.next_raw().await.is_none());
    });
}

#[test]
fn garbage_answer_closes_only_that_connection() {
    run(async {
        let hbbs = start_hbbs().await;
        let mut c = Conn::connect(hbbs.port).await;
        let _offer = c.next().await;
        let mut bad = RendezvousMessage::new();
        bad.set_key_exchange(KeyExchange {
            keys: vec![vec![7u8; 32].into(), vec![9u8; 48].into()],
            ..Default::default()
        });
        c.send(&bad).await;
        assert!(c.next_raw().await.is_none(), "hbbs should close the connection");
        // the server is still fine for the next client
        let mut c = Conn::connect(hbbs.port).await;
        c.secure(&hbbs.pk).await;
        c.send(&punch_request(&hbbs, "nobody", "t")).await;
        assert_eq!(
            punch_failure(&c.next().await),
            Some(punch_hole_response::Failure::ID_NOT_EXIST)
        );
    });
}

