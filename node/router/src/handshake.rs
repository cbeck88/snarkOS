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

use crate::{
    ConnectionMode,
    NodeType,
    PeerPoolHandling,
    Router,
    messages::{
        ChallengeRequest,
        ChallengeResponse,
        DisconnectReason,
        HANDSHAKE_DOMAIN,
        HandshakeHint,
        InitiatorInfo,
        Message,
        MessageCodec,
        MessageTrait,
        PeerInfo,
        ResponderProof,
        decode_payload,
        encode_payload,
    },
};
use snarkos_node_network::{
    get_repo_commit_hash,
    log_repo_sha_comparison,
    noise::{
        HandshakeProtocol,
        NoiseSession,
        PendingSession,
        Role,
        binding_message,
        detect_handshake_protocol,
        prepare_framed,
        write_noise_magic,
    },
};
use snarkos_node_tcp::{ConnectError, ConnectionSide, P2P, Tcp};
use snarkvm::{
    ledger::narwhal::Data,
    prelude::{Address, ConsensusVersion, Field, Network, Signature, block::Header},
};

use anyhow::{Result, anyhow};
use futures::SinkExt;

use std::{io, net::SocketAddr};
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

/// The consensus version at which this node starts *initiating* Noise handshakes on the router, if
/// one is scheduled.
///
/// Only the initiator's choice is gated: a responder accepts either protocol as soon as this code
/// ships, which is what allows nodes to be upgraded one at a time. `None` means no switchover has
/// been scheduled yet - except in development, where the Noise path is always taken so that devnets
/// exercise it, and in tests, which pin the choice explicitly.
///
/// Node types that do not follow the chain height cannot evaluate this at all; see
/// [`Router::initiates_noise_handshake`].
///
/// Setting this is not the end of the migration, only the middle of it; see
/// [`LEGACY_HANDSHAKE_EXPIRY`].
const NOISE_HANDSHAKE_ACTIVATION: Option<ConsensusVersion> = Some(ConsensusVersion::V21);

/// The consensus version at which this node stops *accepting* the legacy handshake on the router, if
/// one is scheduled.
///
/// This is the step that actually collects what the conversion is for. For as long as the responder
/// still accepts the legacy handshake, the unauthenticated `node_type` remains reachable through it,
/// and with it the prover bypass in [`Router::verify_challenge_response`]. Preferring the new path
/// does not close that; refusing the old one does. The same is true of the relay that the handshake
/// binding exists to prevent: the legacy challenge signature covers a pair of nonces and nothing
/// else, so it is valid on any connection it is pasted into - and byte-identical to the one the
/// gateway's legacy handshake produces under the same account key.
///
/// It must trail [`NOISE_HANDSHAKE_ACTIVATION`] by enough for every peer to have switched, as a peer
/// that has not yet reached the activation still dials with the legacy handshake and would be shut
/// out.
// TODO: this needs a consensus version beyond `NOISE_HANDSHAKE_ACTIVATION`, which the pinned
//  snarkVM does not define yet - its `ConsensusVersion` stops at `V21`. Set it once the dependency
//  carries the variant, and settle the prover question below first: a prover's ledger service
//  reports height 0 (`ProverLedgerService::latest_block_height`), so it can neither reach this
//  version nor be shut out by its own copy of it, and provers would keep answering legacy peers
//  after everybody else had stopped.
const LEGACY_HANDSHAKE_EXPIRY: Option<ConsensusVersion> = None;

impl<N: Network> P2P for Router<N> {
    /// Returns a reference to the TCP instance.
    fn tcp(&self) -> &Tcp {
        &self.tcp
    }
}

/// A macro unwrapping the expected handshake message or returning an error for unexpected messages.
#[macro_export]
macro_rules! expect_message {
    ($msg_ty:path, $framed:expr, $peer_addr:expr) => {{
        match $framed.try_next().await? {
            // Received the expected message, proceed.
            Some($msg_ty(data)) => {
                trace!("Received '{}' from '{}'", data.name(), $peer_addr);
                data
            }
            // Received a disconnect message, abort.
            Some(Message::Disconnect($crate::messages::Disconnect { reason })) => {
                return Err(ConnectError::other(format!("'{}' disconnected with reason \"{reason}\"", $peer_addr)));
            }
            // Received an unexpected message, abort.
            Some(ty) => {
                return Err(ConnectError::other(format!(
                    "'{}' did not follow the handshake protocol: received {:?} instead of {}",
                    $peer_addr,
                    ty.name(),
                    stringify!($msg_ty),
                )));
            }
            // Received nothing.
            None => return Err(ConnectError::IoError(io::ErrorKind::BrokenPipe.into())),
        }
    }};
}

/// Send the given message to the peer.
async fn send<N: Network>(
    framed: &mut Framed<&mut TcpStream, MessageCodec<N>>,
    peer_addr: SocketAddr,
    message: Message<N>,
) -> io::Result<()> {
    trace!("Sending '{}' to '{peer_addr}'", message.name());
    framed.send(message).await
}

/// Verifies a peer's signature over the message that binds its Aleo address to a Noise session.
async fn verify_binding_signature<N: Network>(
    peer_addr: SocketAddr,
    signature: Data<Signature<N>>,
    address: Address<N>,
    binding: &[u8],
) -> Option<DisconnectReason> {
    // Perform the deferred non-blocking deserialization of the signature.
    let Ok(signature) = signature.deserialize().await else {
        warn!("Handshake with '{peer_addr}' failed (cannot deserialize the signature)");
        return Some(DisconnectReason::InvalidChallengeResponse);
    };
    // Verify the signature.
    if !signature.verify_bytes(&address, binding) {
        warn!("Handshake with '{peer_addr}' failed (invalid signature)");
        return Some(DisconnectReason::InvalidChallengeResponse);
    }

    None
}

/// Distills a legacy challenge request into the protocol-agnostic peer information.
///
/// The peer's genesis header and restrictions ID are not part of its challenge request but of its
/// challenge response, so they are passed in separately; they are what the peer reported, not what
/// this node expects, since the prover bypass in [`Router::verify_challenge_response`] lets the
/// restrictions ID through unchecked. Nothing downstream reads either field - they exist on
/// [`PeerInfo`] for the Noise path, where they are authenticated - but recording a claim as a claim
/// keeps that true if something ever does.
fn peer_info_from_challenge_request<N: Network>(
    request: ChallengeRequest<N>,
    genesis_header: Header<N>,
    restrictions_id: Field<N>,
) -> PeerInfo<N> {
    let ChallengeRequest { version, listener_port, node_type, address, nonce: _, snarkos_sha } = request;
    PeerInfo { version, listener_port, node_type, address, genesis_header, restrictions_id, snarkos_sha }
}

/// Concludes a Noise handshake, handing the stream back to the connection.
///
/// The stream deliberately goes back unframed: [`Reading`](snarkos_node_tcp::protocols::Reading)
/// builds a message codec of its own and takes full responsibility for the stream from here on.
/// Handing it a bare stream is only sound because the session reads its messages exactly, so
/// anything the peer pipelined behind the last handshake message is still on the socket rather than
/// in a buffer about to be dropped.
fn finish_noise_handshake(noise: NoiseSession<&mut TcpStream>) {
    // Note: the transport keys are discarded here, leaving the resulting connection unencrypted.
    let _stream = noise.into_inner();
}

impl<N: Network> Router<N> {
    /// Executes the handshake protocol.
    pub async fn handshake<'a>(
        &'a self,
        peer_addr: SocketAddr,
        stream: &'a mut TcpStream,
        peer_side: ConnectionSide,
        genesis_header: Header<N>,
        restrictions_id: Field<N>,
    ) -> Result<PeerInfo<N>, ConnectError> {
        // If this is an inbound connection, we log it, but don't know the listening address yet.
        // Otherwise, we can immediately register the listening address.
        let mut listener_addr = if peer_side == ConnectionSide::Initiator {
            debug!("Received a connection request from '{peer_addr}'");
            None
        } else {
            debug!("Shaking hands with '{peer_addr}'...");
            Some(peer_addr)
        };

        // Check (or impose) IP-level bans.
        #[cfg(not(feature = "test"))]
        if !self.is_dev() && peer_side == ConnectionSide::Initiator {
            // If the IP is already banned reject the connection.
            if self.is_ip_banned(peer_addr.ip()) {
                trace!("Rejected a connection request from banned IP '{}'", peer_addr.ip());
                return Err(ConnectError::other(anyhow!("'{}' is a banned IP address", peer_addr.ip())));
            }

            let num_attempts =
                self.cache.insert_inbound_connection(peer_addr.ip(), Router::<N>::CONNECTION_ATTEMPTS_SINCE_SECS);

            debug!("Number of connection attempts from '{}': {}", peer_addr.ip(), num_attempts);
            if num_attempts > Router::<N>::MAX_CONNECTION_ATTEMPTS {
                self.update_ip_ban(peer_addr.ip());
                trace!("Rejected a consecutive connection request from IP '{}'", peer_addr.ip());
                return Err(ConnectError::other(anyhow!("'{}' appears to be spamming connections", peer_addr.ip())));
            }
        }

        // Perform the handshake; we pass on a mutable reference to listener_addr in case the process is broken at any point in time.
        //
        // The initiator picks the handshake protocol, gated on the block height so that nodes can be
        // upgraded one at a time; the responder goes along with whichever one it is offered.
        let handshake_result = match peer_side {
            ConnectionSide::Responder => {
                if self.initiates_noise_handshake() {
                    write_noise_magic(stream).await?;
                    self.handshake_inner_initiator_noise(peer_addr, stream, genesis_header, restrictions_id).await
                } else {
                    self.handshake_inner_initiator(peer_addr, stream, genesis_header, restrictions_id).await
                }
            }
            ConnectionSide::Initiator => match detect_handshake_protocol(stream).await? {
                (HandshakeProtocol::Noise, _) => {
                    self.handshake_inner_responder_noise(
                        peer_addr,
                        &mut listener_addr,
                        stream,
                        genesis_header,
                        restrictions_id,
                    )
                    .await
                }
                (HandshakeProtocol::Legacy, _) if !self.accepts_legacy_handshake() => {
                    Err(ConnectError::other(format!("'{peer_addr}' offered the legacy handshake, which has expired")))
                }
                (HandshakeProtocol::Legacy, prefix) => {
                    self.handshake_inner_responder(
                        peer_addr,
                        &mut listener_addr,
                        stream,
                        genesis_header,
                        restrictions_id,
                        &prefix,
                    )
                    .await
                }
            },
        };

        if let Some(addr) = listener_addr {
            match handshake_result {
                Ok(ref peer_info) => {
                    if let Some(peer) = self.peer_pool.write().get_mut(&addr) {
                        self.resolver.write().insert_peer(peer.listener_addr(), peer_addr, Some(peer_info.address));
                        peer.upgrade_to_connected(
                            peer_addr,
                            peer_info.listener_port,
                            peer_info.address,
                            peer_info.node_type,
                            peer_info.version,
                            peer_info.snarkos_sha,
                            ConnectionMode::Router,
                        );
                    }

                    #[cfg(feature = "metrics")]
                    self.update_metrics();
                }
                Err(_) => {
                    if let Some(peer) = self.peer_pool.write().get_mut(&addr) {
                        // The peer may only be downgraded if it's a ConnectingPeer.
                        if peer.is_connecting() {
                            peer.downgrade_to_candidate(addr);
                        }
                    }
                }
            }
        }

        handshake_result
    }

    /// Returns `true` if this node should offer the Noise handshake when it dials a peer.
    fn initiates_noise_handshake(&self) -> bool {
        // Tests pin the choice, so that both sides of the transition can be covered.
        if let Some(initiates) = self.pinned_handshake_protocol() {
            return initiates;
        }

        // Provers and bootstrap clients do not follow the chain height - a prover's ledger service
        // reports 0 - so they cannot evaluate the activation at all. They take the same line here as
        // they do on the message version (see `Router::is_valid_message_version`) and always speak
        // the latest protocol, which is the only choice that does not leave them dialing a handshake
        // nobody accepts any more once the legacy one expires.
        if !matches!(self.node_type, NodeType::Validator | NodeType::Client) {
            return true;
        }

        // Development nodes always take the new path, so that devnets exercise it.
        self.is_dev() || self.consensus_version_reached(NOISE_HANDSHAKE_ACTIVATION)
    }

    /// Returns `true` if this node still accepts the legacy handshake from a peer that dials it.
    ///
    /// Unlike the choice of what to offer, this is not pinned in tests and not forced in development:
    /// a converted node has to keep answering unconverted ones for the whole of the transition, and
    /// the tests covering that rely on it.
    fn accepts_legacy_handshake(&self) -> bool {
        !self.consensus_version_reached(LEGACY_HANDSHAKE_EXPIRY)
    }

    /// Returns `true` if the given consensus version is scheduled and the ledger has reached it.
    fn consensus_version_reached(&self, version: Option<ConsensusVersion>) -> bool {
        version.is_some_and(|version| {
            N::CONSENSUS_HEIGHT(version).is_ok_and(|height| self.ledger.latest_block_height() >= height)
        })
    }

    /// The pinned choice of handshake protocol; always `None` outside tests.
    #[cfg(not(any(test, feature = "test")))]
    fn pinned_handshake_protocol(&self) -> Option<bool> {
        None
    }

    /// The pinned choice of handshake protocol; see [`Router::initiates_noise_handshake`].
    #[cfg(any(test, feature = "test"))]
    fn pinned_handshake_protocol(&self) -> Option<bool> {
        Some(self.initiates_noise_handshake.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Pins whether this node offers the Noise handshake when it dials, regardless of the activation
    /// height.
    ///
    /// This exists so that tests can cover the transition, during which a converted node still has
    /// to be able to shake hands with unconverted ones.
    #[cfg(any(test, feature = "test"))]
    pub fn set_initiates_noise_handshake(&self, initiates: bool) {
        self.initiates_noise_handshake.store(initiates, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns the snarkOS commit hash to disclose to a peer, if any.
    fn snarkos_sha(&self) -> Option<[u8; 40]> {
        let current_block_height = self.ledger.latest_block_height();
        // The genesis height is always a known consensus version, so this cannot be `None`.
        let consensus_version = N::CONSENSUS_VERSION(current_block_height).unwrap();
        match (consensus_version >= ConsensusVersion::V12, get_repo_commit_hash()) {
            (true, Some(sha)) => Some(sha),
            _ => None,
        }
    }

    /// The metadata this node discloses about itself during a Noise handshake.
    fn our_peer_info(&self, genesis_header: Header<N>, restrictions_id: Field<N>) -> PeerInfo<N> {
        PeerInfo::new(
            self.local_ip().port(),
            self.node_type,
            self.address(),
            genesis_header,
            restrictions_id,
            self.snarkos_sha(),
        )
    }

    /// The connection initiator side of the Noise handshake.
    ///
    /// The initiator does the expensive work first: it signs before the responder has committed to
    /// anything, and only learns whether it was accepted when the fourth message arrives. See
    /// [`Router::handshake_inner_responder_noise`] for the other half of that bargain.
    async fn handshake_inner_initiator_noise<'a>(
        &'a self,
        peer_addr: SocketAddr,
        stream: &'a mut TcpStream,
        genesis_header: Header<N>,
        restrictions_id: Field<N>,
    ) -> Result<PeerInfo<N>, ConnectError> {
        // Introduce the peer into the peer pool.
        // If we are connecting, the peer and listener address are identical.
        self.add_connecting_peer(peer_addr)?;

        let mut noise = NoiseSession::new(stream, Role::Initiator)?;
        let our_info = self.our_peer_info(genesis_header, restrictions_id);

        /* Message 1: announce ourselves in the clear, so the responder can turn us away cheaply. */

        noise.send(&encode_payload(&our_info.hint())?).await?;

        /* Message 2: receive the responder's metadata, which deliberately carries no signature. */

        let peer_info: PeerInfo<N> = decode_payload(peer_addr, &noise.recv().await?)?;

        // The handshake hash at this point already commits to both ephemeral keys, the responder's
        // static key and every payload exchanged so far, so a signature over it is only valid for
        // this session with this responder, and cannot be relayed into another one.
        let binding = binding_message(HANDSHAKE_DOMAIN, Role::Initiator, &noise.handshake_hash()?);

        // Check the peer over before signing anything for it.
        if let Some(reason) = self.verify_peer_info(peer_addr, &peer_info, &genesis_header, restrictions_id) {
            return Err(reason.into_connect_error(peer_addr));
        }

        /* Message 3: disclose ourselves and prove that we own the Aleo address we claim. */

        let Ok(our_signature) = self.account.sign_bytes(&binding, &mut rand::rng()) else {
            return Err(ConnectError::other(anyhow!("Failed to sign the handshake binding")));
        };
        let our_message = InitiatorInfo { info: our_info, signature: Data::Object(our_signature) };
        noise.send(&encode_payload(&our_message)?).await?;

        // Capture the binding for the responder's proof before the hash becomes unavailable; it
        // additionally commits to our static key and to the message we have just sent.
        let peer_binding = binding_message(HANDSHAKE_DOMAIN, Role::Responder, &noise.handshake_hash()?);

        /* Message 4: receive the responder's verdict. */

        let mut noise = noise.into_transport_mode()?;
        let verdict = decode_payload::<ResponderProof<N>>(peer_addr, &noise.recv().await?)?;

        // The pattern is over, so the stream goes back to the connection. The responder considers the
        // handshake done the moment it sent this message and is free to start sending messages while
        // we are still verifying below; those bytes wait on the socket for the message codec.
        finish_noise_handshake(noise);

        let peer_signature = match verdict {
            ResponderProof::Accepted { signature } => signature,
            ResponderProof::Rejected { reason } => {
                warn!("'{peer_addr}' rejected the handshake with reason \"{reason}\"");
                return Err(reason.into_connect_error(peer_addr));
            }
        };

        if let Some(reason) =
            verify_binding_signature(peer_addr, peer_signature, peer_info.address, &peer_binding).await
        {
            return Err(reason.into_connect_error(peer_addr));
        }

        Ok(peer_info)
    }

    /// The connection responder side of the Noise handshake.
    ///
    /// Every expensive operation is deferred for as long as the protocol allows: the responder
    /// verifies a signature only once the initiator's authenticated metadata has passed all of the
    /// cheap checks, and produces one only once that verification has succeeded.
    async fn handshake_inner_responder_noise<'a>(
        &'a self,
        peer_addr: SocketAddr,
        listener_addr: &mut Option<SocketAddr>,
        stream: &'a mut TcpStream,
        genesis_header: Header<N>,
        restrictions_id: Field<N>,
    ) -> Result<PeerInfo<N>, ConnectError> {
        /* Message 1: the peer's cleartext hint. Everything it claims is re-checked in message 3. */

        // The first message is read without deriving any keys, so that everything below costs the
        // responder no more than parsing and lookups until it has decided the peer is worth talking
        // to.
        let pending = PendingSession::accept(stream).await?;
        let hint: HandshakeHint<N> = decode_payload(peer_addr, pending.first_payload()?)?;
        let peer_listener_addr = SocketAddr::new(peer_addr.ip(), hint.listener_port);

        // Turn the peer away before performing any Diffie-Hellman if we already know we do not want
        // it. Nothing here is trustworthy yet - message 3 runs all of it again against the
        // authenticated copy - but every one of these is a peer that would be refused either way.
        if let Err(reason) = self.ensure_peer_is_allowed(peer_listener_addr) {
            return Err(reason.into_connect_error(peer_listener_addr));
        }
        if let Some(reason) = self.verify_peer_claims(peer_addr, hint.version, hint.node_type, hint.address) {
            return Err(reason.into_connect_error(peer_addr));
        }

        // The peer pool is the only thing mutated here, so it goes last: there is no point admitting
        // a peer that one of the checks above was about to turn away. Recording the listening address
        // only once that has succeeded also stops a peer claiming somebody else's port from getting
        // their entry downgraded by failing this handshake.
        self.add_connecting_peer(peer_listener_addr)?;
        *listener_addr = Some(peer_listener_addr);

        /* Message 2: disclose ourselves, but do not sign anything yet. */

        // The peer has passed every free check, so it is now worth deriving keys for.
        let mut noise = pending.into_session()?;

        noise.send(&encode_payload(&self.our_peer_info(genesis_header, restrictions_id))?).await?;

        // The binding the initiator is expected to have signed.
        let peer_binding = binding_message(HANDSHAKE_DOMAIN, Role::Initiator, &noise.handshake_hash()?);

        /* Message 3: the peer's authenticated metadata and its proof of identity. */

        let InitiatorInfo { info: peer_info, signature: peer_signature } =
            decode_payload::<InitiatorInfo<N>>(peer_addr, &noise.recv().await?)?;

        // Our own binding additionally commits to the peer's static key and to the message it has
        // just sent, so it can only be captured after that message has been processed.
        let binding = binding_message(HANDSHAKE_DOMAIN, Role::Responder, &noise.handshake_hash()?);
        let mut noise = noise.into_transport_mode()?;

        // The cleartext hint is a claim, not a fact: reject the peer if it does not match what it
        // has now authenticated, as otherwise the hint would be a way to bypass the checks above.
        if hint != peer_info.hint() {
            warn!("Handshake with '{peer_addr}' failed (the handshake hint was contradicted)");
            return self.reject_noise_handshake(peer_addr, noise, DisconnectReason::ProtocolViolation).await;
        }

        // Everything below is a lookup or a comparison; only once all of it passes is the peer
        // worth the cost of a signature verification.
        if let Some(reason) = self.verify_peer_info(peer_addr, &peer_info, &genesis_header, restrictions_id) {
            return self.reject_noise_handshake(peer_addr, noise, reason).await;
        }

        /* Message 4: having checked the peer over, verify its proof and produce our own. */

        if let Some(reason) =
            verify_binding_signature(peer_addr, peer_signature, peer_info.address, &peer_binding).await
        {
            return self.reject_noise_handshake(peer_addr, noise, reason).await;
        }

        let Ok(our_signature) = self.account.sign_bytes(&binding, &mut rand::rng()) else {
            return Err(ConnectError::other(anyhow!("Failed to sign the handshake binding")));
        };
        noise.send(&encode_payload(&ResponderProof::Accepted { signature: Data::Object(our_signature) })?).await?;

        finish_noise_handshake(noise);

        Ok(peer_info)
    }

    /// Tells the initiator why it was turned away, and fails the handshake with that reason.
    async fn reject_noise_handshake(
        &self,
        peer_addr: SocketAddr,
        mut noise: NoiseSession<&mut TcpStream>,
        reason: DisconnectReason,
    ) -> Result<PeerInfo<N>, ConnectError> {
        noise.send(&encode_payload(&ResponderProof::<N>::Rejected { reason })?).await?;

        Err(reason.into_connect_error(peer_addr))
    }

    /// The connection initiator side of the legacy handshake.
    async fn handshake_inner_initiator<'a>(
        &'a self,
        peer_addr: SocketAddr,
        stream: &'a mut TcpStream,
        genesis_header: Header<N>,
        restrictions_id: Field<N>,
    ) -> Result<PeerInfo<N>, ConnectError> {
        // Introduce the peer into the peer pool.
        // If we are connecting, the peer and listener address are identical.
        self.add_connecting_peer(peer_addr)?;

        // Construct the stream.
        let mut framed = Framed::new(stream, MessageCodec::<N>::handshake());

        /* Step 1: Send the challenge request. */

        // Sample a random nonce.
        let our_nonce: u64 = rand::random();
        // Send a challenge request to the peer.
        let our_request = ChallengeRequest::new(
            self.local_ip().port(),
            self.node_type,
            self.address(),
            our_nonce,
            self.snarkos_sha(),
        );
        send(&mut framed, peer_addr, Message::ChallengeRequest(our_request)).await?;

        /* Step 2: Receive the peer's challenge response followed by the challenge request. */

        // Listen for the challenge response message.
        let peer_response = expect_message!(Message::ChallengeResponse, framed, peer_addr);
        // Listen for the challenge request message.
        let peer_request = expect_message!(Message::ChallengeRequest, framed, peer_addr);

        // Note what the peer reported before the response is consumed by its verification.
        let (peer_genesis_header, peer_restrictions_id) = (peer_response.genesis_header, peer_response.restrictions_id);

        // Verify the challenge response. If a disconnect reason was returned, send the disconnect message and abort.
        if let Some(reason) = self
            .verify_challenge_response(
                peer_addr,
                peer_request.address,
                peer_request.node_type,
                peer_response,
                genesis_header,
                restrictions_id,
                our_nonce,
            )
            .await
        {
            send(&mut framed, peer_addr, reason.into()).await?;
            return Err(reason.into_connect_error(peer_addr));
        }

        // Verify the challenge request. If a disconnect reason was returned, send the disconnect message and abort.
        if let Some(reason) = self.verify_challenge_request(peer_addr, &peer_request) {
            send(&mut framed, peer_addr, reason.into()).await?;
            return Err(reason.into_connect_error(peer_addr));
        }

        /* Step 3: Send the challenge response. */

        let response_nonce: u64 = rand::random();
        let data = [peer_request.nonce.to_le_bytes(), response_nonce.to_le_bytes()].concat();
        // Sign the counterparty nonce.
        let Ok(our_signature) = self.account.sign_bytes(&data, &mut rand::rng()) else {
            return Err(ConnectError::other(anyhow!("Failed to sign the challenge request nonce")));
        };
        // Send the challenge response.
        let our_response = ChallengeResponse {
            genesis_header,
            restrictions_id,
            signature: Data::Object(our_signature),
            nonce: response_nonce,
        };
        send(&mut framed, peer_addr, Message::ChallengeResponse(our_response)).await?;

        Ok(peer_info_from_challenge_request(peer_request, peer_genesis_header, peer_restrictions_id))
    }

    /// The connection responder side of the legacy handshake.
    ///
    /// `prefix` holds the bytes consumed while determining which handshake the peer speaks; they are
    /// the beginning of its first frame.
    #[allow(clippy::too_many_arguments)]
    async fn handshake_inner_responder<'a>(
        &'a self,
        peer_addr: SocketAddr,
        listener_addr: &mut Option<SocketAddr>,
        stream: &'a mut TcpStream,
        genesis_header: Header<N>,
        restrictions_id: Field<N>,
        prefix: &[u8],
    ) -> Result<PeerInfo<N>, ConnectError> {
        // Construct the stream.
        let mut framed = prepare_framed(stream, MessageCodec::<N>::handshake(), prefix);

        /* Step 1: Receive the challenge request. */

        // Wait for the challenge request message.
        let peer_request = expect_message!(Message::ChallengeRequest, framed, peer_addr);

        // Obtain the peer's listening address.
        *listener_addr = Some(SocketAddr::new(peer_addr.ip(), peer_request.listener_port));
        let listener_addr = listener_addr.unwrap();

        // Knowing the peer's listening address, ensure it is allowed to connect.
        if let Err(reason) = self.ensure_peer_is_allowed(listener_addr) {
            send(&mut framed, peer_addr, reason.into()).await?;
            return Err(reason.into_connect_error(listener_addr));
        }

        // Introduce the peer into the peer pool.
        self.add_connecting_peer(listener_addr)?;

        // Verify the challenge request. If a disconnect reason was returned, send the disconnect message and abort.
        if let Some(reason) = self.verify_challenge_request(peer_addr, &peer_request) {
            send(&mut framed, peer_addr, reason.into()).await?;
            return Err(reason.into_connect_error(peer_addr));
        }

        /* Step 2: Send the challenge response followed by own challenge request. */

        // Sign the counterparty nonce.
        let response_nonce: u64 = rand::random();
        let data = [peer_request.nonce.to_le_bytes(), response_nonce.to_le_bytes()].concat();
        let Ok(our_signature) = self.account.sign_bytes(&data, &mut rand::rng()) else {
            return Err(ConnectError::Other(
                anyhow!("Failed to sign the challenge request nonce from '{peer_addr}'").into(),
            ));
        };
        // Send the challenge response.
        let our_response = ChallengeResponse {
            genesis_header,
            restrictions_id,
            signature: Data::Object(our_signature),
            nonce: response_nonce,
        };
        send(&mut framed, peer_addr, Message::ChallengeResponse(our_response)).await?;

        // Sample a random nonce.
        let our_nonce: u64 = rand::random();
        // Send the challenge request.
        let our_request = ChallengeRequest::new(
            self.local_ip().port(),
            self.node_type,
            self.address(),
            our_nonce,
            self.snarkos_sha(),
        );
        send(&mut framed, peer_addr, Message::ChallengeRequest(our_request)).await?;

        /* Step 3: Receive the challenge response. */

        // Wait for the challenge response message.
        let peer_response = expect_message!(Message::ChallengeResponse, framed, peer_addr);

        // Note what the peer reported before the response is consumed by its verification.
        let (peer_genesis_header, peer_restrictions_id) = (peer_response.genesis_header, peer_response.restrictions_id);

        // Verify the challenge response. If a disconnect reason was returned, send the disconnect message and abort.
        if let Some(reason) = self
            .verify_challenge_response(
                peer_addr,
                peer_request.address,
                peer_request.node_type,
                peer_response,
                genesis_header,
                restrictions_id,
                our_nonce,
            )
            .await
        {
            send(&mut framed, peer_addr, reason.into()).await?;
            Err(reason.into_connect_error(peer_addr))
        } else {
            Ok(peer_info_from_challenge_request(peer_request, peer_genesis_header, peer_restrictions_id))
        }
    }

    /// Ensure the peer is allowed to connect.
    fn ensure_peer_is_allowed(&self, listener_addr: SocketAddr) -> Result<(), DisconnectReason> {
        // Ensure that it's not a self-connect attempt.
        if self.is_local_ip(listener_addr) {
            return Err(DisconnectReason::SelfConnect);
        }
        // As a validator, only accept connections from trusted peers and bootstrap nodes.
        if self.node_type() == NodeType::Validator
            && !self.is_trusted(listener_addr)
            && !crate::bootstrap_peers::<N>(self.is_dev()).contains(&listener_addr)
        {
            return Err(DisconnectReason::NoExternalPeersAllowed);
        }
        // If the node is in trusted peers only mode, ensure the peer is explicitly trusted.
        if self.trusted_peers_only() && !self.is_trusted(listener_addr) {
            return Err(DisconnectReason::NoExternalPeersAllowed);
        }

        Ok(())
    }

    /// The checks a peer's claimed identity can be held to without any cryptography, run first
    /// against the cleartext Noise hint and then against the authenticated payload.
    fn verify_peer_claims(
        &self,
        peer_addr: SocketAddr,
        version: u32,
        node_type: NodeType,
        address: Address<N>,
    ) -> Option<DisconnectReason> {
        // Ensure the message protocol version is not outdated.
        if !self.is_valid_message_version(version) {
            warn!("Dropping '{peer_addr}' on version {version} (outdated)");
            return Some(DisconnectReason::OutdatedClientVersion);
        }

        // Ensure there are no validators connected with the given Aleo address.
        if self.node_type() == NodeType::Validator
            && node_type == NodeType::Validator
            && self.is_connected_address(address)
        {
            warn!("Dropping '{peer_addr}' for being already connected ({address})");
            return Some(DisconnectReason::NoReasonGiven);
        }

        None
    }

    /// Verifies the metadata a peer authenticated during a Noise handshake. Returns a disconnect
    /// reason if any of it is unacceptable.
    ///
    /// Unlike [`Router::verify_challenge_response`], the restrictions ID is checked unconditionally.
    /// The prover exemption that path carries only ever existed because a prover had no restrictions
    /// ID to disclose - `ProverLedgerService::latest_restrictions_id` returns zero, having no ledger
    /// to consult - and that is no longer true: the restrictions list is a compile-time constant of
    /// the network, so a prover loads exactly the value everybody else derives from their ledger. An
    /// exemption keyed off `node_type` would in any case be an exemption anybody could claim, since
    /// nothing here is worth trusting until it has been signed for.
    fn verify_peer_info(
        &self,
        peer_addr: SocketAddr,
        info: &PeerInfo<N>,
        expected_genesis_header: &Header<N>,
        expected_restrictions_id: Field<N>,
    ) -> Option<DisconnectReason> {
        log_repo_sha_comparison(peer_addr, &info.snarkos_sha, Self::OWNER);

        // Verify the peer's identity claims.
        if let Some(reason) = self.verify_peer_claims(peer_addr, info.version, info.node_type, info.address) {
            return Some(reason);
        }
        // Verify that the genesis block header matches.
        if &info.genesis_header != expected_genesis_header {
            warn!("Handshake with '{peer_addr}' failed (incorrect block header)");
            return Some(DisconnectReason::InvalidChallengeResponse);
        }
        // Verify the restrictions ID.
        if info.restrictions_id != expected_restrictions_id {
            warn!("Handshake with '{peer_addr}' failed (incorrect restrictions ID)");
            return Some(DisconnectReason::InvalidChallengeResponse);
        }

        None
    }

    /// Verifies the given challenge request. Returns a disconnect reason if the request is invalid.
    fn verify_challenge_request(
        &self,
        peer_addr: SocketAddr,
        message: &ChallengeRequest<N>,
    ) -> Option<DisconnectReason> {
        // Retrieve the components of the challenge request.
        let &ChallengeRequest { version, listener_port: _, node_type, address, nonce: _, ref snarkos_sha } = message;
        log_repo_sha_comparison(peer_addr, snarkos_sha, Self::OWNER);

        self.verify_peer_claims(peer_addr, version, node_type, address)
    }

    /// Verifies the given challenge response. Returns a disconnect reason if the response is invalid.
    ///
    /// Note that neither `peer_node_type` nor the response's restrictions ID is authenticated on this
    /// path: the node type arrives in a plaintext `ChallengeRequest` and the signature covers only
    /// the two nonces. The prover bypass below is therefore something any peer can claim, which is
    /// why it survives only for as long as this handshake does; see [`LEGACY_HANDSHAKE_EXPIRY`] and
    /// [`Router::verify_peer_info`], which is the Noise path's equivalent and has no exemption.
    /// Removing it here instead would reject every prover still running a build that discloses a
    /// zero restrictions ID, and buys little against an adversary in exchange: the restrictions ID is
    /// public, so one that wanted to pass this check could simply echo the right value.
    #[allow(clippy::too_many_arguments)]
    async fn verify_challenge_response(
        &self,
        peer_addr: SocketAddr,
        peer_address: Address<N>,
        peer_node_type: NodeType,
        response: ChallengeResponse<N>,
        expected_genesis_header: Header<N>,
        expected_restrictions_id: Field<N>,
        expected_nonce: u64,
    ) -> Option<DisconnectReason> {
        // Retrieve the components of the challenge response.
        let ChallengeResponse { genesis_header, restrictions_id, signature, nonce } = response;

        // Verify the challenge response, by checking that the block header matches.
        if genesis_header != expected_genesis_header {
            warn!("Handshake with '{peer_addr}' failed (incorrect block header)");
            return Some(DisconnectReason::InvalidChallengeResponse);
        }
        // Verify the restrictions ID.
        if !peer_node_type.is_prover() && !self.node_type.is_prover() && restrictions_id != expected_restrictions_id {
            warn!("Handshake with '{peer_addr}' failed (incorrect restrictions ID)");
            return Some(DisconnectReason::InvalidChallengeResponse);
        }
        // Perform the deferred non-blocking deserialization of the signature.
        let Ok(signature) = signature.deserialize().await else {
            warn!("Handshake with '{peer_addr}' failed (cannot deserialize the signature)");
            return Some(DisconnectReason::InvalidChallengeResponse);
        };
        // Verify the signature.
        if !signature.verify_bytes(&peer_address, &[expected_nonce.to_le_bytes(), nonce.to_le_bytes()].concat()) {
            warn!("Handshake with '{peer_addr}' failed (invalid signature)");
            return Some(DisconnectReason::InvalidChallengeResponse);
        }
        None
    }
}
