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

use snarkos_account::Account;
use snarkos_node_network::{
    NodeType,
    noise::{HandshakeProtocol, PendingSession, Role, binding_message, detect_handshake_protocol, prepare_framed},
};
use snarkos_node_router::{
    expect_message,
    messages::{
        ChallengeRequest,
        ChallengeResponse,
        HANDSHAKE_DOMAIN,
        HandshakeHint,
        InitiatorInfo,
        Message,
        MessageCodec,
        MessageTrait,
        PeerInfo,
        ResponderProof,
    },
};
use snarkos_node_tcp::ConnectError;
use snarkvm::{
    console::network::{MainnetV0 as CurrentNetwork, Network},
    ledger::{
        block::{Block, Header},
        narwhal::Data,
    },
    prelude::{Address, Field, FromBytes, TestRng, ToBytes},
    utilities::into_io_error,
};

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use futures_util::{TryStreamExt, sink::SinkExt};
use pea2pea::{
    Config,
    Connection,
    ConnectionSide,
    DisconnectOrigin,
    Node,
    Pea2Pea,
    protocols::{Handshake, OnDisconnect, Reading, Writing},
};
use rand::RngExt;
use tracing::*;

const ALEO_MAXIMUM_FORK_DEPTH: u32 = 4096;

/// Returns a fixed account.
pub fn sample_account() -> Account<CurrentNetwork> {
    Account::<CurrentNetwork>::from_str("APrivateKey1zkp2oVPTci9kKcUprnbzMwq95Di1MQERpYBhEeqvkrDirK1").unwrap()
}

/// Loads the current network's genesis block.
pub fn sample_genesis_block() -> Block<CurrentNetwork> {
    Block::<CurrentNetwork>::from_bytes_le(CurrentNetwork::genesis_bytes()).unwrap()
}

#[derive(Clone)]
pub struct TestPeer {
    node: Node,
    node_type: NodeType,
    account: Account<CurrentNetwork>,
}

impl Pea2Pea for TestPeer {
    fn node(&self) -> &Node {
        &self.node
    }
}

impl TestPeer {
    pub async fn client() -> Self {
        Self::new(NodeType::Client, sample_account()).await
    }

    pub async fn prover() -> Self {
        Self::new(NodeType::Prover, sample_account()).await
    }

    pub async fn validator() -> Self {
        Self::new(NodeType::Validator, sample_account()).await
    }

    pub async fn new(node_type: NodeType, account: Account<CurrentNetwork>) -> Self {
        let peer = Self {
            node: Node::new(Config {
                max_connections: 200,
                // Everything in these tests shares the loopback address, and the default outside
                // pea2pea's own `test` feature is a single connection per IP.
                max_connections_per_ip: 200,
                listener_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
                ..Default::default()
            }),
            node_type,
            account,
        };

        peer.enable_handshake().await;
        peer.enable_reading().await;
        peer.enable_writing().await;
        peer.enable_on_disconnect().await;

        peer.node().toggle_listener().await.unwrap();

        peer
    }

    /// Returns the address the peer is listening on.
    pub async fn listening_addr(&self) -> SocketAddr {
        self.node().listening_addr().await.expect("listening address should be present")
    }

    pub fn node_type(&self) -> NodeType {
        self.node_type
    }

    pub fn account(&self) -> &Account<CurrentNetwork> {
        &self.account
    }

    pub fn address(&self) -> Address<CurrentNetwork> {
        self.account.address()
    }
}

impl Handshake for TestPeer {
    async fn perform_handshake(&self, conn: Connection) -> io::Result<Connection> {
        self.perform_handshake_inner(conn).await.map_err(into_io_error)
    }
}

impl TestPeer {
    async fn perform_handshake_inner(&self, mut conn: Connection) -> Result<Connection, ConnectError> {
        let rng = &mut TestRng::default();

        let local_ip = self.listening_addr().await;

        let peer_addr = conn.addr();
        let node_side = !conn.side();
        let stream = self.borrow_stream(&mut conn);

        // Retrieve the genesis block header.
        let genesis_header = *sample_genesis_block().header();
        // Retrieve the restrictions ID.
        let restrictions_id = Field::<CurrentNetwork>::from_str(
            "7562506206353711030068167991213732850758501012603348777370400520506564970105field",
        )
        .unwrap();

        // When the node dials, it picks the handshake protocol; when this peer dials, it offers the
        // legacy one, which is what keeps the transition covered from both directions.
        let prefix = if node_side == ConnectionSide::Responder {
            match detect_handshake_protocol(stream).await? {
                (HandshakeProtocol::Noise, _) => {
                    self.perform_noise_handshake(stream, local_ip, genesis_header, restrictions_id).await?;
                    return Ok(conn);
                }
                (HandshakeProtocol::Legacy, prefix) => prefix,
            }
        } else {
            Default::default()
        };
        let mut framed = prepare_framed(stream, MessageCodec::<CurrentNetwork>::default(), &prefix);

        // TODO(nkls): add assertions on the contents of messages.
        match node_side {
            ConnectionSide::Initiator => {
                // Send a challenge request to the peer.
                let our_request =
                    ChallengeRequest::new(local_ip.port(), self.node_type(), self.address(), rng.random(), None);
                framed.send(Message::ChallengeRequest(our_request)).await?;

                // Receive the peer's challenge bundle.
                let _peer_response = expect_message!(Message::ChallengeResponse, framed, peer_addr);
                let peer_request = expect_message!(Message::ChallengeRequest, framed, peer_addr);

                // Sign the nonce.
                let response_nonce: u64 = rng.random();
                let data = [peer_request.nonce.to_le_bytes(), response_nonce.to_le_bytes()].concat();
                let signature = self.account().sign_bytes(&data, rng).unwrap();

                // Send the challenge response.
                let our_response = ChallengeResponse {
                    genesis_header,
                    restrictions_id,
                    signature: Data::Object(signature),
                    nonce: response_nonce,
                };
                framed.send(Message::ChallengeResponse(our_response)).await?;
            }
            ConnectionSide::Responder => {
                // Listen for the challenge request.
                let peer_request = expect_message!(Message::ChallengeRequest, framed, peer_addr);

                // Sign the nonce.
                let response_nonce: u64 = rng.random();
                let data = [peer_request.nonce.to_le_bytes(), response_nonce.to_le_bytes()].concat();
                let signature = self.account().sign_bytes(&data, rng).unwrap();

                // Send our challenge bundle.
                let our_response = ChallengeResponse {
                    genesis_header,
                    restrictions_id,
                    signature: Data::Object(signature),
                    nonce: response_nonce,
                };
                framed.send(Message::ChallengeResponse(our_response)).await?;
                let our_request =
                    ChallengeRequest::new(local_ip.port(), self.node_type(), self.address(), rng.random(), None);
                framed.send(Message::ChallengeRequest(our_request)).await?;

                // Listen for the challenge response.
                let _peer_response = expect_message!(Message::ChallengeResponse, framed, peer_addr);
            }
        }

        Ok(conn)
    }
}

impl TestPeer {
    /// The responder side of the router's Noise handshake.
    ///
    /// This peer authenticates itself honestly and takes whatever the node offers on trust; the
    /// checks are the node's to make, and it is the node under test here.
    async fn perform_noise_handshake(
        &self,
        stream: &mut tokio::net::TcpStream,
        local_ip: SocketAddr,
        genesis_header: Header<CurrentNetwork>,
        restrictions_id: Field<CurrentNetwork>,
    ) -> Result<(), ConnectError> {
        let rng = &mut TestRng::default();

        /* Message 1: the node's cleartext hint. */

        let pending = PendingSession::accept(stream).await?;
        let _hint =
            HandshakeHint::<CurrentNetwork>::from_bytes_le(pending.first_payload()?).map_err(ConnectError::other)?;

        /* Message 2: disclose ourselves. */

        let mut noise = pending.into_session()?;
        let our_info =
            PeerInfo::new(local_ip.port(), self.node_type(), self.address(), genesis_header, restrictions_id, None);
        noise.send(&our_info.to_bytes_le().map_err(ConnectError::other)?).await?;

        /* Message 3: the node's authenticated metadata and proof. */

        let _peer =
            InitiatorInfo::<CurrentNetwork>::from_bytes_le(&noise.recv().await?).map_err(ConnectError::other)?;

        /* Message 4: our own proof. */

        let binding = binding_message(HANDSHAKE_DOMAIN, Role::Responder, &noise.handshake_hash()?);
        let mut noise = noise.into_transport_mode()?;
        let our_signature = self.account().sign_bytes(&binding, rng).unwrap();
        let proof = ResponderProof::<CurrentNetwork>::Accepted { signature: Data::Object(our_signature) };
        noise.send(&proof.to_bytes_le().map_err(ConnectError::other)?).await?;

        Ok(())
    }
}

impl Writing for TestPeer {
    type Codec = MessageCodec<CurrentNetwork>;
    type Message = Message<CurrentNetwork>;

    fn codec(&self, _addr: SocketAddr, _side: ConnectionSide) -> Self::Codec {
        Default::default()
    }
}

impl Reading for TestPeer {
    type Codec = MessageCodec<CurrentNetwork>;
    type Message = Message<CurrentNetwork>;

    fn codec(&self, _peer_addr: SocketAddr, _side: ConnectionSide) -> Self::Codec {
        Default::default()
    }

    async fn process_message(&self, _peer_ip: SocketAddr, _message: Self::Message) {}
}

impl OnDisconnect for TestPeer {
    async fn on_disconnect(&self, _peer_addr: SocketAddr, _origin: DisconnectOrigin) {}
}
