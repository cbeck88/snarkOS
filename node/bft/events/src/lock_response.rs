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

/// A validator's signature over the lock ID of a transaction, in answer to a `LockRequest`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LockResponse<N: Network> {
    pub transmission_id: TransmissionID<N>,
    pub signature: Signature<N>,
}

impl<N: Network> LockResponse<N> {
    /// Initializes a new lock response event.
    pub fn new(transmission_id: TransmissionID<N>, signature: Signature<N>) -> Self {
        Self { transmission_id, signature }
    }
}

impl<N: Network> EventTrait for LockResponse<N> {
    /// Returns the event name.
    #[inline]
    fn name(&self) -> Cow<'static, str> {
        "LockResponse".into()
    }
}

impl<N: Network> ToBytes for LockResponse<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.transmission_id.write_le(&mut writer)?;
        self.signature.write_le(&mut writer)?;
        Ok(())
    }
}

impl<N: Network> FromBytes for LockResponse<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let transmission_id = TransmissionID::read_le(&mut reader)?;
        let signature = Signature::read_le(&mut reader)?;

        Ok(Self { transmission_id, signature })
    }
}

#[cfg(test)]
pub mod prop_tests {
    use crate::{
        LockResponse,
        challenge_response::prop_tests::any_signature,
        lock_certificate::prop_tests::any_transaction_transmission_id,
    };
    use snarkvm::console::prelude::{FromBytes, ToBytes};

    use bytes::{Buf, BufMut, BytesMut};
    use proptest::prelude::{BoxedStrategy, Strategy};
    use test_strategy::proptest;

    type CurrentNetwork = snarkvm::prelude::MainnetV0;

    pub fn any_lock_response() -> BoxedStrategy<LockResponse<CurrentNetwork>> {
        (any_transaction_transmission_id(), any_signature())
            .prop_map(|(transmission_id, signature)| LockResponse::new(transmission_id, signature))
            .boxed()
    }

    #[proptest]
    fn serialize_deserialize(#[strategy(any_lock_response())] original: LockResponse<CurrentNetwork>) {
        let mut buf = BytesMut::default().writer();
        LockResponse::write_le(&original, &mut buf).unwrap();

        let deserialized: LockResponse<CurrentNetwork> = LockResponse::read_le(buf.into_inner().reader()).unwrap();
        assert_eq!(original, deserialized);
    }
}
