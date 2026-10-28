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

/// A lock key of a transaction: an input it spends, visible in its plaintext and bound to its signer.
///
/// At most one pending transaction per key is admitted to the memory pool, and at most one is lock-signed.
///
/// A key must be one that only the transaction's signer could take, because every validator takes
/// it in the lock round after `check_transaction_basic` alone, before finalize ever runs. The payer
/// of a public fee is (`fee_public` debits `self.signer`), and so is a serial number (consuming the
/// record needs its owner's key). The address a `credits.aleo` call debits is not, so it is no key:
/// `transfer_public`, `bond_public`, `unbond_public` and `transfer_public_to_private` pass
/// `self.caller` to finalize, which is the calling program's address when another program calls
/// them, so every user of such a program would share one key and anyone could hold the program's
/// lock for one fee per block; and `unbond_public` debits the staker, whom the signer need not
/// control (the withdrawal-address check is in finalize), so anyone could hold a validator's lock
/// for one fee per block. A race on a non-fee public debit ends in a rejection with the fee paid,
/// not an abort, so nothing the locks are for is lost by leaving it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LockKey<N: Network> {
    /// The payer of a public fee.
    Payer(Address<N>),
    /// The serial number of a record consumed by a private fee, or by a transaction without a fee.
    SerialNumber(Field<N>),
}

impl<N: Network> LockKey<N> {
    /// Returns the lock keys of the given transaction: the payer of its public fee, or the serial
    /// numbers its private fee consumes.
    ///
    /// The keys of a transaction without a fee are the serial numbers of the records it consumes; whether
    /// it is exempt from the fee is left to the VM's full check. One that consumes no record is refused.
    pub fn from_transaction(transaction: &Transaction<N>) -> Result<Vec<Self>> {
        let keys = match transaction.fee_transition() {
            Some(fee) => match (fee.is_fee_public(), fee.payer()) {
                (true, Some(payer)) => vec![Self::Payer(payer)],
                (true, None) => bail!("Transaction '{}' has a public fee without a payer", transaction.id()),
                (false, _) => fee.serial_numbers().map(|serial_number| Self::SerialNumber(*serial_number)).collect(),
            },
            None => transaction.serial_numbers().map(|serial_number| Self::SerialNumber(*serial_number)).collect(),
        };
        ensure!(!keys.is_empty(), "Transaction '{}' has no lock key", transaction.id());
        Ok(keys)
    }

    /// Returns the serial number, if this is a serial number key.
    pub fn serial_number(&self) -> Option<&Field<N>> {
        match self {
            Self::SerialNumber(serial_number) => Some(serial_number),
            Self::Payer(_) => None,
        }
    }
}

impl<N: Network> ToBytes for LockKey<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Payer(address) => {
                0u8.write_le(&mut writer)?;
                address.write_le(&mut writer)
            }
            Self::SerialNumber(serial_number) => {
                1u8.write_le(&mut writer)?;
                serial_number.write_le(&mut writer)
            }
        }
    }
}

impl<N: Network> FromBytes for LockKey<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        match u8::read_le(&mut reader)? {
            0 => Ok(Self::Payer(Address::read_le(&mut reader)?)),
            1 => Ok(Self::SerialNumber(Field::read_le(&mut reader)?)),
            2.. => Err(error("Invalid lock key variant")),
        }
    }
}

#[cfg(test)]
pub mod prop_tests {
    use crate::{LockKey, certificate_request::prop_tests::any_field};
    use snarkvm::{
        console::prelude::{FromBytes, ToBytes},
        prelude::{Address, TestRng, Uniform},
    };

    use bytes::{Buf, BufMut, BytesMut};
    use proptest::{
        collection,
        prelude::{BoxedStrategy, Strategy, any},
        prop_oneof,
    };
    use test_strategy::proptest;

    type CurrentNetwork = snarkvm::prelude::MainnetV0;

    pub fn any_lock_key() -> BoxedStrategy<LockKey<CurrentNetwork>> {
        prop_oneof![
            any::<u8>().prop_map(|_| LockKey::Payer(Address::rand(&mut TestRng::default()))),
            any_field().prop_map(LockKey::SerialNumber),
        ]
        .boxed()
    }

    pub fn any_lock_keys() -> BoxedStrategy<Vec<LockKey<CurrentNetwork>>> {
        collection::vec(any_lock_key(), 1..=4).boxed()
    }

    #[proptest]
    fn serialize_deserialize(#[strategy(any_lock_key())] original: LockKey<CurrentNetwork>) {
        let mut buf = BytesMut::default().writer();
        LockKey::write_le(&original, &mut buf).unwrap();

        let deserialized: LockKey<CurrentNetwork> = LockKey::read_le(buf.into_inner().reader()).unwrap();
        assert_eq!(original, deserialized);
    }
}
