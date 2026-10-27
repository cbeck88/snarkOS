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

use snarkvm::ledger::block::Transaction;

/// A validator's request to the committee to sign a lock for a transaction it has checked in full.
///
/// The transaction travels with the request, so that a responder can check it before signing, and
/// the requester's own signature over the lock ID is included: it is the first of the certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockRequest<N: Network> {
    pub transmission_id: TransmissionID<N>,
    pub keys: Vec<LockKey<N>>,
    pub transaction: Data<Transaction<N>>,
    pub signature: Signature<N>,
}

impl<N: Network> LockRequest<N> {
    /// Initializes a new lock request event.
    pub fn new(
        transmission_id: TransmissionID<N>,
        keys: Vec<LockKey<N>>,
        transaction: Data<Transaction<N>>,
        signature: Signature<N>,
    ) -> Self {
        Self { transmission_id, keys, transaction, signature }
    }
}

impl<N: Network> EventTrait for LockRequest<N> {
    /// Returns the event name.
    #[inline]
    fn name(&self) -> Cow<'static, str> {
        "LockRequest".into()
    }
}

impl<N: Network> ToBytes for LockRequest<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.transmission_id.write_le(&mut writer)?;
        u16::try_from(self.keys.len()).map_err(error)?.write_le(&mut writer)?;
        for key in &self.keys {
            key.write_le(&mut writer)?;
        }
        self.transaction.write_le(&mut writer)?;
        self.signature.write_le(&mut writer)?;
        Ok(())
    }
}

impl<N: Network> FromBytes for LockRequest<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let transmission_id = TransmissionID::read_le(&mut reader)?;
        let num_keys = u16::read_le(&mut reader)?;
        if num_keys as usize > LockCertificate::<N>::MAX_KEYS {
            return Err(error(format!(
                "Number of lock keys ({num_keys}) exceeds the maximum ({})",
                LockCertificate::<N>::MAX_KEYS
            )));
        }
        let keys = (0..num_keys).map(|_| LockKey::read_le(&mut reader)).collect::<IoResult<Vec<_>>>()?;
        let transaction = Data::read_le(&mut reader)?;
        let signature = Signature::read_le(&mut reader)?;

        Ok(Self { transmission_id, keys, transaction, signature })
    }
}

#[cfg(test)]
pub mod prop_tests {
    use crate::{
        LockRequest,
        challenge_response::prop_tests::any_signature,
        lock_certificate::prop_tests::any_transaction_transmission_id,
        lock_key::prop_tests::any_lock_keys,
    };
    use snarkvm::{
        console::prelude::{FromBytes, ToBytes},
        ledger::narwhal::Data,
    };

    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use proptest::{
        collection,
        prelude::{BoxedStrategy, Strategy, any},
    };
    use test_strategy::proptest;

    type CurrentNetwork = snarkvm::prelude::MainnetV0;

    pub fn any_lock_request() -> BoxedStrategy<LockRequest<CurrentNetwork>> {
        (any_transaction_transmission_id(), any_lock_keys(), collection::vec(any::<u8>(), 512..=512), any_signature())
            .prop_map(|(transmission_id, keys, bytes, signature)| {
                LockRequest::new(transmission_id, keys, Data::Buffer(Bytes::from(bytes)), signature)
            })
            .boxed()
    }

    #[proptest]
    fn serialize_deserialize(#[strategy(any_lock_request())] original: LockRequest<CurrentNetwork>) {
        let mut buf = BytesMut::default().writer();
        LockRequest::write_le(&original, &mut buf).unwrap();

        let deserialized = LockRequest::read_le(buf.into_inner().reader()).unwrap();
        assert_eq!(original, deserialized);
    }
}
