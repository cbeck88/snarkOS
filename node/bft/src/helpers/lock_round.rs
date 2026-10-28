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

use crate::events::{LockCertificate, LockKey};
use snarkvm::{
    console::{
        account::{Address, Signature},
        network::Network,
        types::Field,
    },
    ledger::{committee::Committee, narwhal::TransmissionID},
    prelude::{Result, bail, ensure},
};

use indexmap::IndexSet;
use std::collections::HashSet;
use tokio::sync::oneshot;

/// A lock round this primary is running for a transaction it checked: the signatures collected so
/// far, and the channel on which the certificate is delivered once a quorum has signed.
pub struct LockRound<N: Network> {
    /// The locked transmission.
    transmission_id: TransmissionID<N>,
    /// The lock keys.
    keys: Vec<LockKey<N>>,
    /// The lock ID, which the committee signs.
    lock_id: Field<N>,
    /// The committee whose quorum certifies the lock.
    committee: Committee<N>,
    /// The signatures over the lock ID.
    signatures: IndexSet<Signature<N>>,
    /// The signer of each signature, in the same order.
    signers: Vec<Address<N>>,
    /// Delivers the certificate; taken once the lock is certified.
    certified: Option<oneshot::Sender<LockCertificate<N>>>,
}

impl<N: Network> LockRound<N> {
    /// Initializes a lock round for the given transmission and keys, under the given committee.
    pub fn new(
        transmission_id: TransmissionID<N>,
        keys: Vec<LockKey<N>>,
        committee: Committee<N>,
        certified: oneshot::Sender<LockCertificate<N>>,
    ) -> Result<Self> {
        let lock_id = LockCertificate::<N>::lock_id(&transmission_id, &keys)?;
        Ok(Self {
            transmission_id,
            keys,
            lock_id,
            committee,
            signatures: Default::default(),
            signers: Default::default(),
            certified: Some(certified),
        })
    }

    /// Returns the lock ID.
    pub const fn lock_id(&self) -> Field<N> {
        self.lock_id
    }

    /// Returns the number of signatures collected.
    pub fn num_signatures(&self) -> usize {
        self.signatures.len()
    }

    /// Returns the number of members of the committee.
    pub fn num_members(&self) -> usize {
        self.committee.num_members()
    }

    /// Adds a signature over the lock ID from the given committee member, returning `true` if it is
    /// new and `false` if the member already signed.
    pub fn add_signature(&mut self, signer: Address<N>, signature: Signature<N>) -> Result<bool> {
        if !self.committee.is_committee_member(signer) {
            bail!("Lock signature from a non-committee member - '{signer}'")
        }
        if self.signers.contains(&signer) {
            return Ok(false);
        }
        if !signature.verify(&signer, &[self.lock_id]) {
            bail!("Lock signature verification failed")
        }
        self.signatures.insert(signature);
        self.signers.push(signer);
        Ok(true)
    }

    /// Returns `true` if the signers reach the quorum threshold of the committee.
    pub fn is_quorum_threshold_reached(&self) -> bool {
        self.committee.is_quorum_threshold_reached(&self.signers.iter().copied().collect::<HashSet<_>>())
    }

    /// Returns `true` if the lock has been certified.
    pub fn is_certified(&self) -> bool {
        self.certified.is_none()
    }

    /// Assembles the certificate from the signatures collected, and delivers it.
    pub fn certify(&mut self) -> Result<()> {
        ensure!(self.is_quorum_threshold_reached(), "The quorum threshold has not been reached");
        let Some(certified) = self.certified.take() else { bail!("The lock is already certified") };
        let certificate = LockCertificate::from_signers(
            self.transmission_id,
            self.keys.clone(),
            self.signatures.clone(),
            self.signers.clone(),
        )?;
        // The receiver is gone only if the originator stopped waiting, in which case there is nothing to do.
        certified.send(certificate).ok();
        Ok(())
    }
}
