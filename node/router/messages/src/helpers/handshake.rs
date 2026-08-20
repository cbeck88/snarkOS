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

//! The payloads carried by the messages of the router's Noise handshake.
//!
//! These mirror the gateway's payloads in
//! [`snarkos_node_bft_events::helpers::handshake`], and the four messages have the same shape:
//!
//! 1. `->` [`HandshakeHint`] - cleartext, so the responder can bail out before doing any work.
//! 2. `<-` [`PeerInfo`] - the responder's metadata, deliberately without a signature.
//! 3. `->` [`InitiatorInfo`] - the initiator's metadata *and* the proof of its identity.
//! 4. `<-` [`ResponderProof`] - the responder's verdict, and its own proof if the initiator checked
//!    out. This is the first transport message, the pattern having ended with the third.
//!
//! What the router adds over the gateway is `node_type`, which the gateway does not need because
//! everything it talks to is a validator, and the genesis header, which the router has always
//! exchanged in order to keep peers from different networks apart.
//!
//! # Why this closes the hole the legacy handshake left open
//!
//! The legacy [`ChallengeRequest`](crate::ChallengeRequest) carries `node_type` in the clear and
//! signs only a pair of nonces, so a peer could declare itself a prover and have the restrictions
//! check skipped on the strength of an unauthenticated byte. Here both `node_type` and
//! `restrictions_id` travel inside [`PeerInfo`], which is covered by the signature over the
//! handshake hash - by the hash itself for the responder's copy, and by the AEAD tag of the message
//! that carries it for the initiator's. Altering either field invalidates the proof, so the checks
//! that read them are checks on authenticated data rather than on a claim.
//!
//! See the module documentation of the gateway's equivalent for the full account of which mechanism
//! binds which message; it applies here unchanged.

use crate::{Disconnect, DisconnectReason, Message};
use snarkos_node_network::{ConnectionMode, NodeType};
use snarkvm::{
    console::prelude::{FromBytes, Network, Read, ToBytes, Write, io_error},
    ledger::narwhal::Data,
    prelude::{Address, Field, Signature, block::Header},
};

use std::io::Result as IoResult;

/// The domain separator for the signatures binding an Aleo address to a router Noise session.
///
/// This must differ from the gateway's `HANDSHAKE_DOMAIN`: a validator runs both subprotocols
/// concurrently under one Aleo key, so a shared domain would let a signature obtained on one be
/// replayed into the other. Domain separation is the entire reason [`binding_message`] takes the
/// parameter.
///
/// [`binding_message`]: snarkos_node_network::noise::binding_message
pub const HANDSHAKE_DOMAIN: &[u8] = b"snarkos-router-handshake-v1";

/// Serializes a handshake payload for transmission inside a Noise message.
///
/// Re-exported from the gateway's handshake module rather than reimplemented: the two subprotocols
/// differ in what they put in a Noise message, not in how a payload becomes bytes.
pub use snarkos_node_bft_events::{decode_payload, encode_payload};

/// Constant for an unknown commit hash.
const UNKNOWN_COMMIT_HASH: [u8; 40] = [b'?'; 40];

/// The cleartext payload of the first handshake message.
///
/// It is neither encrypted nor authenticated, so it must be treated as a claim rather than a fact.
/// It exists so that the responder can turn away peers it would never accept - self-connects,
/// outdated versions, untrusted peers when running in trusted-peers-only mode, external peers when
/// running as a validator - before performing a single Diffie-Hellman operation. Every field
/// reappears in [`PeerInfo`], where it is authenticated, and the responder must reject the
/// connection if the two disagree; otherwise this message would be a way to be checked as one peer
/// and admitted as another.
///
/// The payload opens with the connection mode, so that a bootstrap client - which accepts both the
/// gateway's and the router's connections on one listener - knows which hint it is reading before it
/// parses the rest; see [`ConnectionMode`]. A hint for a different mode is rejected by name rather
/// than misread as this one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeHint<N: Network> {
    pub version: u32,
    pub listener_port: u16,
    pub node_type: NodeType,
    pub address: Address<N>,
}

impl<N: Network> HandshakeHint<N> {
    /// The connection mode this hint describes; the router's handshake only ever serves one.
    pub const MODE: ConnectionMode = ConnectionMode::Router;
}

impl<N: Network> ToBytes for HandshakeHint<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        Self::MODE.write_le(&mut writer)?;
        self.version.write_le(&mut writer)?;
        self.listener_port.write_le(&mut writer)?;
        self.node_type.write_le(&mut writer)?;
        self.address.write_le(&mut writer)
    }
}

impl<N: Network> FromBytes for HandshakeHint<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let mode = ConnectionMode::read_le(&mut reader)?;
        if mode != Self::MODE {
            return Err(io_error(format!("expected a {}-mode handshake, got {mode}", Self::MODE)));
        }

        let version = u32::read_le(&mut reader)?;
        let listener_port = u16::read_le(&mut reader)?;
        let node_type = NodeType::read_le(&mut reader)?;
        let address = Address::<N>::read_le(&mut reader)?;

        Ok(Self { version, listener_port, node_type, address })
    }
}

/// What a party discloses about itself during the handshake.
///
/// This is the payload of the second message on its own, and part of the payload of the third; it
/// is also what a completed handshake hands back to the router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerInfo<N: Network> {
    pub version: u32,
    pub listener_port: u16,
    pub node_type: NodeType,
    pub address: Address<N>,
    pub genesis_header: Header<N>,
    pub restrictions_id: Field<N>,
    pub snarkos_sha: Option<[u8; 40]>,
}

impl<N: Network> PeerInfo<N> {
    pub fn new(
        listener_port: u16,
        node_type: NodeType,
        address: Address<N>,
        genesis_header: Header<N>,
        restrictions_id: Field<N>,
        snarkos_sha: Option<[u8; 40]>,
    ) -> Self {
        Self {
            version: Message::<N>::latest_message_version(),
            listener_port,
            node_type,
            address,
            genesis_header,
            restrictions_id,
            snarkos_sha,
        }
    }

    /// The hint this info would have been announced with, for comparing the two.
    pub const fn hint(&self) -> HandshakeHint<N> {
        HandshakeHint {
            version: self.version,
            listener_port: self.listener_port,
            node_type: self.node_type,
            address: self.address,
        }
    }
}

impl<N: Network> ToBytes for PeerInfo<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.version.write_le(&mut writer)?;
        self.listener_port.write_le(&mut writer)?;
        self.node_type.write_le(&mut writer)?;
        self.address.write_le(&mut writer)?;
        self.genesis_header.write_le(&mut writer)?;
        self.restrictions_id.write_le(&mut writer)?;
        // Serialize `None` as a constant.
        self.snarkos_sha.unwrap_or(UNKNOWN_COMMIT_HASH).write_le(&mut writer)
    }
}

impl<N: Network> FromBytes for PeerInfo<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let version = u32::read_le(&mut reader)?;
        let listener_port = u16::read_le(&mut reader)?;
        let node_type = NodeType::read_le(&mut reader)?;
        let address = Address::<N>::read_le(&mut reader)?;
        let genesis_header = Header::read_le(&mut reader)?;
        let restrictions_id = Field::read_le(&mut reader)?;
        // Unlike the legacy `ChallengeRequest`, a missing SHA is an error rather than a `None`: the
        // payload is delimited by the Noise message, so a short read is a protocol violation.
        let snarkos_sha = <[u8; 40]>::read_le(&mut reader)?;
        let snarkos_sha = if snarkos_sha == UNKNOWN_COMMIT_HASH { None } else { Some(snarkos_sha) };

        Ok(Self { version, listener_port, node_type, address, genesis_header, restrictions_id, snarkos_sha })
    }
}

/// The payload of the third handshake message: the initiator's metadata, plus the signature that
/// binds its Aleo address to this session.
///
/// The initiator signs first by design. Verifying the signature is the most expensive thing the
/// responder does, and it only reaches that point once every cheap check against `info` has passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiatorInfo<N: Network> {
    pub info: PeerInfo<N>,
    pub signature: Data<Signature<N>>,
}

impl<N: Network> ToBytes for InitiatorInfo<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.info.write_le(&mut writer)?;
        self.signature.write_le(&mut writer)
    }
}

impl<N: Network> FromBytes for InitiatorInfo<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let info = PeerInfo::read_le(&mut reader)?;
        let signature = Data::read_le(&mut reader)?;

        Ok(Self { info, signature })
    }
}

/// The payload of the fourth handshake message: the responder's verdict.
///
/// The responder's proof is sent separately from its [`PeerInfo`], and last, so that it never signs
/// anything for a peer that has not already authenticated itself. If the initiator was turned away
/// instead, this message carries the reason: the initiator dialed in and has no other way to find
/// out, whereas a responder that gets rejected is owed nothing and is simply dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponderProof<N: Network> {
    /// The initiator was accepted; the signature binds the responder's Aleo address to the session.
    Accepted { signature: Data<Signature<N>> },
    /// The initiator was rejected.
    Rejected { reason: DisconnectReason },
}

impl<N: Network> ToBytes for ResponderProof<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Accepted { signature } => {
                0u8.write_le(&mut writer)?;
                signature.write_le(&mut writer)
            }
            Self::Rejected { reason } => {
                1u8.write_le(&mut writer)?;
                // Reuse the message's encoding of the reason, which rejects the unknown variant.
                Disconnect::from(*reason).write_le(&mut writer)
            }
        }
    }
}

impl<N: Network> FromBytes for ResponderProof<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        match u8::read_le(&mut reader)? {
            0 => Ok(Self::Accepted { signature: Data::read_le(&mut reader)? }),
            1 => Ok(Self::Rejected { reason: Disconnect::read_le(&mut reader)?.reason }),
            variant => Err(io_error(format!("Invalid responder proof variant ({variant})"))),
        }
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use crate::{
        challenge_request::prop_tests::{any_node_type, any_valid_address},
        challenge_response::prop_tests::any_genesis_header,
    };

    use snarkvm::{
        console::prelude::{FromBytes, ToBytes},
        prelude::{Address, TestRng, Uniform},
    };

    use bytes::{Buf, BufMut, BytesMut};
    use proptest::{
        collection,
        prelude::{BoxedStrategy, Strategy, any},
    };
    use test_strategy::proptest;

    type CurrentNetwork = snarkvm::prelude::MainnetV0;

    /// The one thing that must hold of the two domains: a signature produced for one subprotocol
    /// must not verify for the other, which a validator running both under a single Aleo key relies
    /// on. See [`HANDSHAKE_DOMAIN`].
    #[test]
    fn the_router_and_gateway_domains_differ() {
        assert_ne!(HANDSHAKE_DOMAIN, snarkos_node_bft_events::HANDSHAKE_DOMAIN);
    }

    fn any_peer_info() -> BoxedStrategy<PeerInfo<CurrentNetwork>> {
        (
            any_valid_address(),
            any_node_type(),
            any_genesis_header(),
            any::<u32>(),
            any::<u16>(),
            any::<u64>(),
            collection::vec(0u8..=127, 40),
        )
            .prop_map(|(address, node_type, genesis_header, version, listener_port, seed, sha)| {
                let sha: [u8; 40] = sha.try_into().unwrap();
                let snarkos_sha = if sha == UNKNOWN_COMMIT_HASH { None } else { Some(sha) };
                PeerInfo {
                    version,
                    listener_port,
                    node_type,
                    address,
                    genesis_header,
                    restrictions_id: Field::rand(&mut TestRng::fixed(seed)),
                    snarkos_sha,
                }
            })
            .boxed()
    }

    #[proptest]
    fn handshake_hint_serialize_deserialize(
        #[strategy(any::<(u32, u16)>())] fields: (u32, u16),
        #[strategy(any_node_type())] node_type: NodeType,
        #[strategy(any_valid_address())] address: Address<CurrentNetwork>,
    ) {
        let original = HandshakeHint { version: fields.0, listener_port: fields.1, node_type, address };

        let mut buf = BytesMut::default().writer();
        original.write_le(&mut buf).unwrap();

        let deserialized = HandshakeHint::<CurrentNetwork>::read_le(buf.into_inner().reader()).unwrap();
        assert_eq!(original, deserialized);
    }

    #[proptest]
    fn peer_info_serialize_deserialize(#[strategy(any_peer_info())] original: PeerInfo<CurrentNetwork>) {
        let mut buf = BytesMut::default().writer();
        original.write_le(&mut buf).unwrap();

        let deserialized = PeerInfo::read_le(buf.into_inner().reader()).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn rejected_responder_proof_serialize_deserialize() {
        for reason in [
            DisconnectReason::OutdatedClientVersion,
            DisconnectReason::ProtocolViolation,
            DisconnectReason::InvalidChallengeResponse,
        ] {
            let original = ResponderProof::<CurrentNetwork>::Rejected { reason };

            let mut buf = BytesMut::default().writer();
            original.write_le(&mut buf).unwrap();

            let deserialized = ResponderProof::<CurrentNetwork>::read_le(buf.into_inner().reader()).unwrap();
            assert_eq!(original, deserialized);
        }
    }
}
