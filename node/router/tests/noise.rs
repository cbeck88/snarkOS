// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkOS library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! End-to-end tests for the router's Noise handshake.

#[allow(dead_code)]
mod common;

use crate::common::{TestRouter, client, prover, sample_account, sample_genesis_block, validator};
use snarkos_account::Account;
use snarkos_node_network::{
    NodeType,
    PeerPoolHandling,
    noise::{
        HandshakeProtocol,
        MAX_HANDSHAKE_MSG_LEN,
        NoiseSession,
        Role,
        binding_message,
        detect_handshake_protocol,
        write_noise_magic,
    },
};
use snarkos_node_router::messages::{
    HANDSHAKE_DOMAIN,
    HandshakeHint,
    InitiatorInfo,
    Message,
    PeerInfo,
    ResponderProof,
};
use snarkos_node_tcp::{P2P, protocols::Handshake};
use snarkvm::{
    ledger::narwhal::Data,
    prelude::{Address, Field, FromBytes, MainnetV0 as CurrentNetwork, TestRng, ToBytes, block::Header},
};

use std::{io, net::SocketAddr, str::FromStr, time::Duration};

use anyhow::Result;

use deadline::deadline;
use tokio::{
    net::{TcpListener, TcpStream},
    task,
};

/// The gateway's binding domain, as of `snarkos_node_bft_events::HANDSHAKE_DOMAIN`.
///
/// It is spelled out rather than imported, the router not depending on the gateway's events. That
/// the two are actually different is pinned by a unit test in the router's messages crate; what this
/// copy is for is proving that a signature produced under it does not open a router connection.
const GATEWAY_HANDSHAKE_DOMAIN: &[u8] = b"snarkos-bft-handshake-v1";

/// The restrictions ID a `TestRouter` expects of its peers; see its `Handshake` implementation.
fn expected_restrictions_id() -> Field<CurrentNetwork> {
    Field::from_str("7562506206353711030068167991213732850758501012603348777370400520506564970105field").unwrap()
}

/// The genesis header a `TestRouter` expects of its peers.
fn expected_genesis_header() -> Header<CurrentNetwork> {
    *sample_genesis_block::<CurrentNetwork>().header()
}

/// Brings up a listening router with its handshake enabled.
async fn running_client(rng: &mut TestRng) -> TestRouter<CurrentNetwork> {
    let router = client(0, 10, rng).await;
    router.enable_handshake().await;
    router.tcp().enable_listener().await.unwrap();
    router
}

/// What a hand-rolled peer offers a router during the handshake.
///
/// The fields are separate from `PeerInfo` so that a test can have the hint disagree with the
/// authenticated payload, which is a thing only a dishonest peer can do.
struct PeerOffer {
    hint_node_type: NodeType,
    node_type: NodeType,
    restrictions_id: Field<CurrentNetwork>,
    genesis_header: Header<CurrentNetwork>,
    domain: &'static [u8],
    /// Applied to the serialized third message, after it has been signed.
    ///
    /// The signature covers the handshake hash rather than this payload, so tampering here does not
    /// invalidate it; what stops the altered field from being believed is the responder's own
    /// checks, which is exactly what this exists to probe.
    tamper: fn(&mut Vec<u8>),
}

impl PeerOffer {
    /// An offer that a router should accept.
    fn honest(node_type: NodeType) -> Self {
        Self {
            hint_node_type: node_type,
            node_type,
            restrictions_id: expected_restrictions_id(),
            genesis_header: expected_genesis_header(),
            domain: HANDSHAKE_DOMAIN,
            tamper: |_| {},
        }
    }
}

/// Drives a Noise handshake against a router by hand, up to and including the verdict.
///
/// The peer authenticates honestly - it holds the key it claims - and differs from a real one only
/// in what it puts in the payloads, which is what makes it useful for probing the checks.
async fn handshake_with_router(
    router_addr: SocketAddr,
    account: &Account<CurrentNetwork>,
    listener_port: u16,
    offer: &PeerOffer,
) -> Result<ResponderProof<CurrentNetwork>> {
    let mut stream = TcpStream::connect(router_addr).await?;
    write_noise_magic(&mut stream).await?;
    let mut noise = NoiseSession::new(&mut stream, Role::Initiator)?;

    let version = Message::<CurrentNetwork>::latest_message_version();

    // Message 1: the cleartext hint.
    let hint = HandshakeHint { version, listener_port, node_type: offer.hint_node_type, address: account.address() };
    noise.send(&hint.to_bytes_le()?).await?;

    // Message 2: the router's metadata.
    let _router_info = PeerInfo::<CurrentNetwork>::from_bytes_le(&noise.recv().await?)?;

    // Message 3: our metadata, and the proof that we hold the address it names.
    let binding = binding_message(offer.domain, Role::Initiator, &noise.handshake_hash()?);
    let signature = account.sign_bytes(&binding, &mut rand::rng()).unwrap();
    let our_info = PeerInfo::new(
        listener_port,
        offer.node_type,
        account.address(),
        offer.genesis_header,
        offer.restrictions_id,
        None,
    );
    let our_message = InitiatorInfo { info: our_info, signature: Data::Object(signature) };
    let mut payload = our_message.to_bytes_le()?;
    (offer.tamper)(&mut payload);
    noise.send(&payload).await?;

    // Message 4: the verdict.
    let mut noise = noise.into_transport_mode()?;
    ResponderProof::from_bytes_le(&noise.recv().await?)
}

/// Asserts that the router turned the peer away, and did not admit it.
fn assert_rejected(
    verdict: Result<ResponderProof<CurrentNetwork>>,
    address: Address<CurrentNetwork>,
    router: &TestRouter<CurrentNetwork>,
) {
    match verdict {
        // The router may either name the reason or hang up; both are refusals.
        Ok(ResponderProof::Rejected { .. }) | Err(_) => {}
        Ok(ResponderProof::Accepted { .. }) => panic!("the router accepted the peer"),
    }
    assert!(!router.is_connected_address(address), "the peer reached the peer pool");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_routers_complete_a_noise_handshake() {
    let mut rng = TestRng::default();
    let (node0, node1) = (running_client(&mut rng).await, running_client(&mut rng).await);

    node0.tcp().connect(node1.local_ip()).await.unwrap();

    // Both sides must have authenticated the other's Aleo address, not merely completed a TCP
    // connection.
    let (a, b) = (node0.clone(), node1.clone());
    let (addr_a, addr_b) = (node0.address(), node1.address());
    deadline!(Duration::from_secs(5), move || { a.is_connected_address(addr_b) && b.is_connected_address(addr_a) });
}

/// During the transition, a node that speaks Noise still has to be able to shake hands with one that
/// only knows the legacy handshake - which is every node until the activation height passes. The
/// responder goes along with whichever protocol it is offered, and the legacy path now reaches it
/// through the protocol detection, which consumes the first four bytes of the peer's opening frame
/// and has to feed them back into the message codec.
#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_initiator_is_accepted_by_a_noise_capable_responder() {
    let mut rng = TestRng::default();
    let (node0, node1) = (running_client(&mut rng).await, running_client(&mut rng).await);

    // Stand in for an unconverted node: dial with the legacy handshake.
    node0.set_initiates_noise_handshake(false);
    node0.tcp().connect(node1.local_ip()).await.unwrap();

    let (a, b) = (node0.clone(), node1.clone());
    let (addr_a, addr_b) = (node0.address(), node1.address());
    deadline!(Duration::from_secs(5), move || { a.is_connected_address(addr_b) && b.is_connected_address(addr_a) });
}

/// The reported defect: the legacy handshake skips the restrictions check whenever either side says
/// it is a prover, and the claim is unauthenticated. Under Noise there is no such exemption, so a
/// peer declaring itself a prover is held to the restrictions ID like everybody else.
#[tokio::test(flavor = "multi_thread")]
async fn a_spoofed_prover_with_a_mismatched_restrictions_id_is_rejected() {
    let mut rng = TestRng::default();
    let router = running_client(&mut rng).await;
    let peer = sample_account(&mut rng);

    let offer =
        PeerOffer { restrictions_id: Field::from_str("1field").unwrap(), ..PeerOffer::honest(NodeType::Prover) };
    let verdict = handshake_with_router(router.local_ip(), &peer, 4130, &offer).await;

    assert_rejected(verdict, peer.address(), &router);
}

/// The exemption is gone rather than merely bypassed: an honest prover, which now discloses the same
/// restrictions ID as everybody else, still gets in.
#[tokio::test(flavor = "multi_thread")]
async fn an_honest_prover_is_accepted() {
    let mut rng = TestRng::default();
    let router = running_client(&mut rng).await;
    let peer = sample_account(&mut rng);

    let verdict = handshake_with_router(router.local_ip(), &peer, 4130, &PeerOffer::honest(NodeType::Prover)).await;

    assert!(matches!(verdict, Ok(ResponderProof::Accepted { .. })), "an honest prover should be accepted");
}

/// A local node is exempt from nothing either: a prover checks its peers' restrictions ID, where the
/// legacy handshake let it skip the comparison entirely.
#[tokio::test(flavor = "multi_thread")]
async fn a_prover_checks_its_peers_restrictions_id() {
    let mut rng = TestRng::default();
    let router = prover(0, 10, &mut rng).await;
    router.enable_handshake().await;
    router.tcp().enable_listener().await.unwrap();
    let peer = sample_account(&mut rng);

    let offer =
        PeerOffer { restrictions_id: Field::from_str("1field").unwrap(), ..PeerOffer::honest(NodeType::Client) };
    let verdict = handshake_with_router(router.local_ip(), &peer, 4130, &offer).await;

    assert_rejected(verdict, peer.address(), &router);
}

/// The node type the responder runs its early checks against is a claim; the one it admits the peer
/// under is authenticated. A peer that says one thing in the clear and another under signature is
/// turned away rather than being checked as one and recorded as the other.
#[tokio::test(flavor = "multi_thread")]
async fn a_contradicted_node_type_is_rejected() {
    let mut rng = TestRng::default();
    let router = running_client(&mut rng).await;
    let peer = sample_account(&mut rng);

    let offer = PeerOffer { hint_node_type: NodeType::Client, ..PeerOffer::honest(NodeType::Prover) };
    let verdict = handshake_with_router(router.local_ip(), &peer, 4130, &offer).await;

    assert_rejected(verdict, peer.address(), &router);
}

/// The genesis header check the legacy handshake performed survives the conversion, and is now part
/// of the payload the peer signs for rather than of an unauthenticated message.
///
/// A peer cannot even construct a header claiming to be a genesis it is not - `Header::from_bytes_le`
/// enforces the network's genesis values at height zero - so the tampering is done on the wire
/// bytes, after the payload has been built and signed. Note that the signature stays valid, covering
/// the handshake hash and not this payload; it is the responder that has to refuse it.
#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_genesis_header_is_rejected() {
    let mut rng = TestRng::default();
    let router = running_client(&mut rng).await;
    let peer = sample_account(&mut rng);

    // The header's timestamp is the last of its fields, and `PeerInfo` writes the restrictions ID
    // and the commit hash after it; move it on by a second where it sits in the serialized message.
    let offer = PeerOffer {
        tamper: |payload| {
            // The header is written verbatim into the payload, and its timestamp is its last field.
            let header = expected_genesis_header().to_bytes_le().unwrap();
            let start = payload
                .windows(header.len())
                .position(|window| window == header)
                .expect("the genesis header should appear in the payload");
            let timestamp = start + header.len() - std::mem::size_of::<i64>();
            let moved = i64::from_le_bytes(payload[timestamp..timestamp + 8].try_into().unwrap()) + 1;
            payload[timestamp..timestamp + 8].copy_from_slice(&moved.to_le_bytes());
        },
        ..PeerOffer::honest(NodeType::Client)
    };
    let verdict = handshake_with_router(router.local_ip(), &peer, 4130, &offer).await;

    assert_rejected(verdict, peer.address(), &router);
}

/// A validator runs the gateway and the router concurrently under one Aleo key. If the two signed
/// the same message, a signature collected on either could be replayed into the other; the binding
/// domains are what stop that.
#[tokio::test(flavor = "multi_thread")]
async fn a_gateway_binding_does_not_open_a_router_connection() {
    let mut rng = TestRng::default();
    let router = running_client(&mut rng).await;
    let peer = sample_account(&mut rng);

    let offer = PeerOffer { domain: GATEWAY_HANDSHAKE_DOMAIN, ..PeerOffer::honest(NodeType::Client) };
    let verdict = handshake_with_router(router.local_ip(), &peer, 4130, &offer).await;

    assert_rejected(verdict, peer.address(), &router);
}

/// Relays a Noise handshake between a victim that dials `listener` and a `target` it believes it is
/// talking to.
///
/// This is the attack the handshake binding exists to defeat: the attacker terminates a Noise
/// session on each side and forwards the decrypted payloads verbatim, so that both ends believe they
/// authenticated each other while it sits in the middle with plaintext access to both.
///
/// Against the legacy handshake this works, because the challenge signatures cover only a pair of
/// nonces and are therefore valid on any connection they are pasted into. Against this one it must
/// not, because each side signs its own session's handshake hash and the two sessions cannot have
/// the same one.
async fn relay_noise_handshake(listener: TcpListener, target: SocketAddr) -> io::Result<()> {
    let (mut victim_stream, _) = listener.accept().await?;

    // The victim announced the Noise handshake; consume the marker and answer as the responder.
    let (protocol, _) = detect_handshake_protocol(&mut victim_stream).await?;
    assert_eq!(protocol, HandshakeProtocol::Noise);
    let mut from_victim = NoiseSession::new(victim_stream, Role::Responder)?;

    // Open a second, entirely independent session to the target.
    let mut target_stream = TcpStream::connect(target).await?;
    write_noise_magic(&mut target_stream).await?;
    let mut to_target = NoiseSession::new(target_stream, Role::Initiator)?;

    // Forward each payload from one session into the other.
    let hint = from_victim.recv().await?;
    to_target.send(&hint).await?;

    let responder_info = to_target.recv().await?;
    from_victim.send(&responder_info).await?;

    let initiator_info = from_victim.recv().await?;
    to_target.send(&initiator_info).await?;

    let mut to_target = to_target.into_transport_mode()?;
    let mut from_victim = from_victim.into_transport_mode()?;

    let verdict = to_target.recv().await?;
    from_victim.send(&verdict).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_noise_handshake_is_rejected() {
    let mut rng = TestRng::default();
    let (node0, node1) = (running_client(&mut rng).await, running_client(&mut rng).await);

    // Put the attacker between the two routers.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let target = node1.local_ip();
    let relay = task::spawn(async move { relay_noise_handshake(listener, target).await });

    // The victim dials the attacker, believing it to be a peer.
    assert!(node0.tcp().connect(relay_addr).await.is_err(), "the relayed handshake should have been rejected");

    // Neither side may end up considering the other a peer.
    assert!(!node0.is_connected_address(node1.address()));
    assert!(!node1.is_connected_address(node0.address()));

    relay.abort();
}

/// A validator only takes trusted peers and bootstrap nodes, and turns everything else away before
/// the pattern begins - which is the point of checking there, but leaves it no channel to say so.
#[tokio::test(flavor = "multi_thread")]
async fn a_validator_turns_an_untrusted_peer_away_before_deriving_keys() {
    let mut rng = TestRng::default();
    let router = validator(0, 10, &[], true, &mut rng).await;
    router.enable_handshake().await;
    router.tcp().enable_listener().await.unwrap();
    let peer = sample_account(&mut rng);

    let mut stream = TcpStream::connect(router.local_ip()).await.unwrap();
    write_noise_magic(&mut stream).await.unwrap();
    let mut noise = NoiseSession::new(&mut stream, Role::Initiator).unwrap();

    let hint = HandshakeHint::<CurrentNetwork> {
        version: Message::<CurrentNetwork>::latest_message_version(),
        listener_port: 4130,
        node_type: NodeType::Client,
        address: peer.address(),
    };
    noise.send(&hint.to_bytes_le().unwrap()).await.unwrap();

    // Never receiving a second message is what proves it spent no Diffie-Hellman on this peer.
    assert!(noise.recv().await.is_err(), "the validator should not have replied to an untrusted peer");
    assert!(!router.is_connected_address(peer.address()));
}

/// The router's handshake carries the genesis header, which the gateway's does not, so its third
/// message is by some way the largest thing either subprotocol asks a Noise message to hold. This
/// pins that it still fits, with room for a field or two to be added later.
#[test]
fn the_largest_handshake_message_fits_a_noise_message() {
    let mut rng = TestRng::default();
    let account = sample_account(&mut rng);

    let info = PeerInfo::<CurrentNetwork>::new(
        4130,
        NodeType::Client,
        account.address(),
        expected_genesis_header(),
        expected_restrictions_id(),
        Some([b'a'; 40]),
    );
    let signature = account.sign_bytes(b"binding", &mut rand::rng()).unwrap();
    let message = InitiatorInfo { info, signature: Data::Object(signature) };

    // A generous stand-in for what the pattern adds on top of a payload: an ephemeral public key, an
    // encrypted static public key, and an AEAD tag for each of the static key and the payload.
    const NOISE_OVERHEAD: usize = 128;
    let len = message.to_bytes_le().unwrap().len() + NOISE_OVERHEAD;

    assert!(len < MAX_HANDSHAKE_MSG_LEN, "the third handshake message is {len} bytes, over the Noise limit");
}
