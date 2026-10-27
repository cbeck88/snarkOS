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

use snarkvm::{
    console::program::{Argument, Literal, Plaintext},
    ledger::block::Transaction,
};

/// The `credits.aleo` functions whose finalize debits a public balance, with the position of the
/// debited address among the arguments of the future each of them outputs.
///
/// Every one of these takes the debited address as a public input of its finalize, so the address
/// is visible in the plaintext of the transition's future output without executing it. `bond_public`,
/// `bond_validator` and `unbond_public` move credits between an account and its bond rather than out
/// of an account, but each still reduces a public balance of the listed address.
const DEBITING_FUNCTIONS: [(&str, usize); 7] = [
    ("transfer_public", 0),
    ("transfer_public_as_signer", 0),
    ("transfer_public_to_private", 0),
    ("bond_public", 0),
    ("bond_validator", 0),
    ("unbond_public", 1),
    ("fee_public", 0),
];

/// A lock key of a transaction: an input it spends, visible in its plaintext.
///
/// At most one pending transaction per key is admitted to the memory pool, and at most one is lock-signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LockKey<N: Network> {
    /// A public address whose balance the transaction debits: the payer of a public fee, or the
    /// debited address of a `credits.aleo` call (see [`DEBITING_FUNCTIONS`]).
    Payer(Address<N>),
    /// The serial number of a record consumed by a private fee, or by a transaction without a fee.
    SerialNumber(Field<N>),
}

impl<N: Network> LockKey<N> {
    /// Returns the lock keys of the given transaction, without duplicates: the key of its fee, then
    /// the public address debited by each `credits.aleo` call among its transitions.
    ///
    /// The keys of a transaction without a fee are the serial numbers of the records it consumes; whether
    /// it is exempt from the fee is left to the VM's full check. One that consumes no record is refused.
    pub fn from_transaction(transaction: &Transaction<N>) -> Result<Vec<Self>> {
        let mut keys = match transaction.fee_transition() {
            Some(fee) => match (fee.is_fee_public(), fee.payer()) {
                (true, Some(payer)) => vec![Self::Payer(payer)],
                (true, None) => bail!("Transaction '{}' has a public fee without a payer", transaction.id()),
                (false, _) => fee.serial_numbers().map(|serial_number| Self::SerialNumber(*serial_number)).collect(),
            },
            None => transaction.serial_numbers().map(|serial_number| Self::SerialNumber(*serial_number)).collect(),
        };
        ensure!(!keys.is_empty(), "Transaction '{}' has no lock key", transaction.id());
        // Widen to every public address the transaction debits through `credits.aleo`.
        for transition in transaction.transitions().filter(|transition| transition.is_credits()) {
            let function_name = transition.function_name().to_string();
            let Some((_, index)) = DEBITING_FUNCTIONS.iter().find(|(name, _)| *name == function_name) else {
                continue;
            };
            let Some(future) = transition.outputs().iter().find_map(|output| output.future()) else {
                bail!("Transition '{}' of transaction '{}' outputs no future", transition.id(), transaction.id());
            };
            ensure!(
                future.program_id().to_string() == "credits.aleo"
                    && future.function_name().to_string() == function_name,
                "Transition '{}' of transaction '{}' outputs a future of another function",
                transition.id(),
                transaction.id()
            );
            let Some(Argument::Plaintext(Plaintext::Literal(Literal::Address(address), _))) =
                future.arguments().get(*index)
            else {
                bail!("Transition '{}' of transaction '{}' has no debited address", transition.id(), transaction.id());
            };
            let key = Self::Payer(*address);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
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
