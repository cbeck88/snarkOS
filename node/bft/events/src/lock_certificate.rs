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

use super::*;

use snarkvm::{ledger::committee::Committee, prelude::ToBits};

use std::{collections::HashSet, sync::OnceLock};

/// A quorum of committee signatures over a transaction's lock: its transmission ID and its lock keys.
///
/// A validator signs a lock for at most one pending transaction per key, so two transactions with a
/// key in common cannot both be certified. The certificate travels with the transmission (see
/// `TransmissionResponse`), and a batch proposal is signed only if every transaction it names
/// carries one from the committee of its round. It is not part of the block.
///
/// This mirrors `BatchCertificate`: the signers are recovered once, on verification, and cached.
#[derive(Clone, Debug)]
pub struct LockCertificate<N: Network> {
    /// The locked transmission.
    transmission_id: TransmissionID<N>,
    /// The lock keys of the transaction (see [`LockKey::from_transaction`]).
    keys: Vec<LockKey<N>>,
    /// The signatures over the lock ID, the originator's included.
    signatures: IndexSet<Signature<N>>,
    /// The recovered address of each signer, in the same order as `signatures`. Derived, cached,
    /// never serialized, and not part of `PartialEq` or `Hash`.
    signers: OnceLock<Vec<Address<N>>>,
}

impl<N: Network> LockCertificate<N> {
    /// The maximum number of lock keys in a certificate: a transaction has one key per fee and at
    /// most one per transition, and far fewer transitions than this.
    pub const MAX_KEYS: usize = 64;

    /// The maximum number of signatures in a lock certificate.
    pub fn max_signatures() -> u16 {
        N::LATEST_MAX_CERTIFICATES()
    }

    /// Returns the lock ID: the message the committee signs for the given transmission and keys.
    pub fn lock_id(transmission_id: &TransmissionID<N>, keys: &[LockKey<N>]) -> Result<Field<N>> {
        let mut preimage = Vec::new();
        // Separate the domain from the batch IDs, which the same key signs.
        preimage.extend_from_slice(b"lock");
        1u8.write_le(&mut preimage)?;
        transmission_id.write_le(&mut preimage)?;
        u16::try_from(keys.len())?.write_le(&mut preimage)?;
        for key in keys {
            key.write_le(&mut preimage)?;
        }
        N::hash_bhp1024(&preimage.to_bits_le())
    }

    /// Initializes a new lock certificate from signatures that were each already verified over the
    /// lock ID, with their signers in the same order.
    pub fn from_signers(
        transmission_id: TransmissionID<N>,
        keys: Vec<LockKey<N>>,
        signatures: IndexSet<Signature<N>>,
        signers: Vec<Address<N>>,
    ) -> Result<Self> {
        ensure!(signatures.len() == signers.len(), "Each lock signature needs a signer");
        let certificate = Self::from_unchecked(transmission_id, keys, signatures)?;
        let _ = certificate.signers.set(signers);
        Ok(certificate)
    }

    /// Initializes a new lock certificate without checking the signatures (see [`Self::verify`]).
    pub fn from_unchecked(
        transmission_id: TransmissionID<N>,
        keys: Vec<LockKey<N>>,
        signatures: IndexSet<Signature<N>>,
    ) -> Result<Self> {
        ensure!(matches!(transmission_id, TransmissionID::Transaction(..)), "Only a transaction can be locked");
        ensure!(!keys.is_empty() && keys.len() <= Self::MAX_KEYS, "Invalid number of lock keys");
        ensure!(!signatures.is_empty(), "Lock certificate must contain signatures");
        ensure!(signatures.len() <= Self::max_signatures() as usize, "Invalid number of signatures");
        Ok(Self { transmission_id, keys, signatures, signers: OnceLock::new() })
    }

    /// Returns the locked transmission ID.
    pub const fn transmission_id(&self) -> &TransmissionID<N> {
        &self.transmission_id
    }

    /// Returns the lock keys.
    pub fn keys(&self) -> &[LockKey<N>] {
        &self.keys
    }

    /// Returns the signatures.
    pub fn signatures(&self) -> impl '_ + ExactSizeIterator<Item = &Signature<N>> {
        self.signatures.iter()
    }

    /// Returns the address of each signer, recovering them on first use (one fixed-base scalar
    /// multiplication each).
    pub fn signers(&self) -> &[Address<N>] {
        self.signers.get_or_init(|| self.signatures.iter().map(Signature::to_address).collect())
    }

    /// Returns `true` if the signers reach the quorum threshold of the given committee.
    ///
    /// This does not verify the signatures (see [`Self::verify`]); it is the cheap check that a
    /// certificate issued under one committee still holds under another.
    pub fn is_quorum_threshold_reached(&self, committee: &Committee<N>) -> bool {
        let signers = self.signers().iter().copied().collect::<HashSet<_>>();
        signers.len() == self.signatures.len()
            && signers.iter().all(|signer| committee.is_committee_member(*signer))
            && committee.is_quorum_threshold_reached(&signers)
    }

    /// Verifies the certificate against the given committee: every signature is from a distinct
    /// committee member and valid over the lock ID, and the signers reach the quorum threshold.
    pub fn verify(&self, committee: &Committee<N>) -> Result<()> {
        let lock_id = Self::lock_id(&self.transmission_id, &self.keys)?;
        let signatures = self.signatures.iter().collect::<Vec<_>>();
        let signers = self.signers();
        ensure!(signatures.len() == signers.len(), "Each lock signature needs a signer");
        // Ensure the signers are distinct committee members reaching quorum.
        let signer_set = signers.iter().copied().collect::<HashSet<_>>();
        ensure!(signer_set.len() == signers.len(), "A duplicate signer was found in the lock certificate");
        if let Some(signer) = signers.iter().find(|signer| !committee.is_committee_member(**signer)) {
            bail!("Lock certificate signer '{signer}' is not a committee member");
        }
        ensure!(committee.is_quorum_threshold_reached(&signer_set), "Lock certificate has no quorum");
        // Verify the signatures.
        // Note: This is sequential; a caller checking many certificates parallelizes across them.
        for (signature, signer) in signatures.iter().zip(signers) {
            ensure!(signature.verify(signer, &[lock_id]), "Invalid lock certificate signature");
        }
        Ok(())
    }
}

impl<N: Network> PartialEq for LockCertificate<N> {
    fn eq(&self, other: &Self) -> bool {
        self.transmission_id == other.transmission_id && self.keys == other.keys && self.signatures == other.signatures
    }
}

impl<N: Network> Eq for LockCertificate<N> {}

impl<N: Network> ToBytes for LockCertificate<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        1u8.write_le(&mut writer)?;
        self.transmission_id.write_le(&mut writer)?;
        u16::try_from(self.keys.len()).map_err(error)?.write_le(&mut writer)?;
        for key in &self.keys {
            key.write_le(&mut writer)?;
        }
        u16::try_from(self.signatures.len()).map_err(error)?.write_le(&mut writer)?;
        for signature in &self.signatures {
            signature.write_le(&mut writer)?;
        }
        Ok(())
    }
}

impl<N: Network> FromBytes for LockCertificate<N> {
    /// Reads the certificate, without verifying its signatures: that needs a committee, and is done
    /// where the certificate is used (see [`LockCertificate::verify`]).
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let version = u8::read_le(&mut reader)?;
        if version != 1 {
            return Err(error("Invalid lock certificate version"));
        }
        let transmission_id = TransmissionID::read_le(&mut reader)?;
        let num_keys = u16::read_le(&mut reader)?;
        if num_keys as usize > Self::MAX_KEYS {
            return Err(error(format!("Number of lock keys ({num_keys}) exceeds the maximum ({})", Self::MAX_KEYS)));
        }
        let keys = (0..num_keys).map(|_| LockKey::read_le(&mut reader)).collect::<IoResult<Vec<_>>>()?;
        let num_signatures = u16::read_le(&mut reader)?;
        if num_signatures > Self::max_signatures() {
            return Err(error(format!(
                "Number of signatures ({num_signatures}) exceeds the maximum ({})",
                Self::max_signatures()
            )));
        }
        let signatures =
            (0..num_signatures).map(|_| Signature::read_le(&mut reader)).collect::<IoResult<IndexSet<_>>>()?;
        // A repeated signature would give one certificate a second encoding.
        if signatures.len() != num_signatures as usize {
            return Err(error("Duplicate signature in lock certificate"));
        }
        Self::from_unchecked(transmission_id, keys, signatures).map_err(error)
    }
}

#[cfg(test)]
pub mod prop_tests {
    use crate::{
        LockCertificate,
        lock_key::prop_tests::any_lock_keys,
        prop_tests::{any_transaction_id, any_transmission_checksum},
    };
    use snarkvm::{
        console::prelude::{FromBytes, ToBytes},
        ledger::narwhal::TransmissionID,
        prelude::{PrivateKey, Signature, TestRng},
    };

    use bytes::{Buf, BufMut, BytesMut};
    use indexmap::IndexSet;
    use proptest::prelude::{BoxedStrategy, Strategy};
    use test_strategy::proptest;

    type CurrentNetwork = snarkvm::prelude::MainnetV0;

    pub fn any_transaction_transmission_id() -> BoxedStrategy<TransmissionID<CurrentNetwork>> {
        (any_transaction_id(), any_transmission_checksum())
            .prop_map(|(id, checksum)| TransmissionID::Transaction(id, checksum))
            .boxed()
    }

    pub fn any_lock_certificate() -> BoxedStrategy<LockCertificate<CurrentNetwork>> {
        (any_transaction_transmission_id(), any_lock_keys(), 1..4usize)
            .prop_map(|(transmission_id, keys, num_signatures)| {
                let rng = &mut TestRng::default();
                let lock_id = LockCertificate::lock_id(&transmission_id, &keys).unwrap();
                let signatures = (0..num_signatures)
                    .map(|_| Signature::sign(&PrivateKey::new(rng).unwrap(), &[lock_id], rng).unwrap())
                    .collect::<IndexSet<_>>();
                LockCertificate::from_unchecked(transmission_id, keys, signatures).unwrap()
            })
            .boxed()
    }

    #[proptest]
    fn serialize_deserialize(#[strategy(any_lock_certificate())] original: LockCertificate<CurrentNetwork>) {
        let mut buf = BytesMut::default().writer();
        LockCertificate::write_le(&original, &mut buf).unwrap();

        let deserialized = LockCertificate::read_le(buf.into_inner().reader()).unwrap();
        assert_eq!(original, deserialized);
    }
}
