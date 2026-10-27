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

//! The lock keys and the lock table live in the BFT, which shares one table between admission here
//! and lock signing in the primary; this module keeps the key-extraction tests with the admission rule.

pub use snarkos_node_bft::helpers::{InputLocks, LockKey};

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::{
        algorithms::snark::varuna::VarunaVersion,
        circuit::AleoV0,
        ledger::{
            Transaction,
            query::Query,
            store::{BlockStore, helpers::memory::BlockMemory},
            test_helpers::{
                sample_deployment_transaction,
                sample_execution,
                sample_execution_transaction_with_fee,
                sample_genesis_block_and_components,
            },
        },
        prelude::*,
        synthesizer::Process,
    };

    use aleo_std::StorageMode;

    type CurrentNetwork = MainnetV0;

    /// Samples a fee-less transaction with a single `credits.aleo/split` transition.
    fn sample_split_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        let (block, transactions, private_key) = sample_genesis_block_and_components(rng);
        let record = transactions.iter().next().unwrap().records().next().unwrap().1.clone();
        let record = record.decrypt(&ViewKey::try_from(&private_key).unwrap()).unwrap();
        let process = Process::load().unwrap();
        let authorization = process
            .authorize::<AleoV0, _>(
                &private_key,
                "credits.aleo",
                "split",
                [Value::Record(record), Value::from_str("1000000u64").unwrap()].iter(),
                rng,
            )
            .unwrap();
        let (_, mut trace) = process.execute::<AleoV0, _>(authorization, rng).unwrap();
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        block_store.insert(&block).unwrap();
        trace.prepare(&Query::from(block_store)).unwrap();
        let execution = trace.prove_execution::<AleoV0, _>("credits.aleo/split", VarunaVersion::V1, rng).unwrap();
        Transaction::from_execution(execution, None).unwrap()
    }

    /// Samples a `credits.aleo/transfer_public` from the genesis account to a random address, paying
    /// a private fee from a genesis record if `is_fee_private`, and a public fee otherwise.
    fn sample_transfer_public_transaction(is_fee_private: bool, rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        let (block, transactions, private_key) = sample_genesis_block_and_components(rng);
        let process = Process::load().unwrap();
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        block_store.insert(&block).unwrap();
        let query = Query::from(block_store);

        // The transfer.
        let recipient = Address::<CurrentNetwork>::rand(rng);
        let authorization = process
            .authorize::<AleoV0, _>(
                &private_key,
                "credits.aleo",
                "transfer_public",
                [Value::from_str(&recipient.to_string()).unwrap(), Value::from_str("1000000u64").unwrap()].iter(),
                rng,
            )
            .unwrap();
        let (_, mut trace) = process.execute::<AleoV0, _>(authorization, rng).unwrap();
        trace.prepare(&query).unwrap();
        let execution =
            trace.prove_execution::<AleoV0, _>("credits.aleo/transfer_public", VarunaVersion::V1, rng).unwrap();
        let execution_id = execution.to_execution_id().unwrap();

        // The fee.
        let (base_fee, priority_fee) = (10_000_000, 1_000);
        let authorization = match is_fee_private {
            true => {
                let record = transactions.iter().next().unwrap().records().next().unwrap().1.clone();
                let record = record.decrypt(&ViewKey::try_from(&private_key).unwrap()).unwrap();
                process
                    .authorize_fee_private::<AleoV0, _>(&private_key, record, base_fee, priority_fee, execution_id, rng)
                    .unwrap()
            }
            false => process
                .authorize_fee_public::<AleoV0, _>(&private_key, base_fee, priority_fee, execution_id, rng)
                .unwrap(),
        };
        let (_, mut trace) = process.execute::<AleoV0, _>(authorization, rng).unwrap();
        trace.prepare(&query).unwrap();
        let fee = trace.prove_fee::<AleoV0, _>(VarunaVersion::V1, rng).unwrap();

        Transaction::from_execution(execution, Some(fee)).unwrap()
    }

    #[test]
    fn lock_keys_of_transactions_with_a_fee() {
        let rng = &mut TestRng::default();

        // A public fee locks its payer.
        let transaction = sample_execution_transaction_with_fee(false, rng, 0);
        let fee = transaction.fee_transition().unwrap();
        assert_eq!(LockKey::from_transaction(&transaction).unwrap(), vec![LockKey::Payer(fee.payer().unwrap())]);

        // A private fee locks the serial number of its record, then the address the sampled execution (a
        // genesis `credits.aleo` call from the genesis account) debits.
        let transaction = sample_execution_transaction_with_fee(true, rng, 0);
        let fee = transaction.fee_transition().unwrap();
        let mut keys = fee.serial_numbers().map(|sn| LockKey::SerialNumber(*sn)).collect::<Vec<_>>();
        assert_eq!(keys.len(), 1);
        let (_, _, private_key) = sample_genesis_block_and_components(rng);
        keys.push(LockKey::Payer(Address::try_from(&private_key).unwrap()));
        assert_eq!(LockKey::from_transaction(&transaction).unwrap(), keys);

        // A deployment's fee locks the same way.
        let transaction = sample_deployment_transaction(2, 0, false, false, rng);
        let fee = transaction.fee_transition().unwrap();
        assert_eq!(LockKey::from_transaction(&transaction).unwrap(), vec![LockKey::Payer(fee.payer().unwrap())]);
    }

    #[test]
    fn lock_keys_of_transactions_without_a_fee() {
        let rng = &mut TestRng::default();

        // A fee-less execution that consumes no record has no lock key, and is refused.
        // Note: One that consumes a record is keyed by its serial numbers, whether or not it is a split or upgrade;
        // the ledger's `check_fee` checks it in full, and the VM refuses it unless it is exempt from the fee.
        let transaction = Transaction::from_execution(sample_execution(rng, 0), None).unwrap();
        assert!(transaction.fee_transition().is_none());
        assert!(!transaction.contains_split() && !transaction.contains_upgrade());
        assert_eq!(transaction.serial_numbers().count(), 0);
        assert!(LockKey::from_transaction(&transaction).is_err());

        // A lone split locks the record it consumes, once.
        let transaction = sample_split_transaction(rng);
        assert!(transaction.fee_transition().is_none());
        let keys = LockKey::from_transaction(&transaction).unwrap();
        let serial_numbers = transaction.serial_numbers().map(|sn| LockKey::SerialNumber(*sn)).collect::<Vec<_>>();
        assert_eq!(serial_numbers.len(), 1);
        assert_eq!(keys, serial_numbers);
        let mut locks = InputLocks::<CurrentNetwork>::default();
        locks.insert(transaction.id(), keys.clone(), 0).unwrap();
        assert!(locks.check(&keys).is_err());
    }

    /// A transaction that debits a public balance takes that address's key as well as its fee's key,
    /// so a private-fee `transfer_public` cannot drain an address while a public-fee transaction from
    /// it is pending; a public-fee `transfer_public` from the payer takes the one key once.
    #[test]
    fn a_public_debit_widens_the_keys() {
        let rng = &mut TestRng::default();
        let (_, _, private_key) = sample_genesis_block_and_components(rng);
        let sender = LockKey::Payer(Address::try_from(&private_key).unwrap());

        // A private fee: the record's serial number, then the debited address.
        let transaction = sample_transfer_public_transaction(true, rng);
        let fee = transaction.fee_transition().unwrap();
        assert!(!fee.is_fee_public());
        let serial_number = LockKey::SerialNumber(*fee.serial_numbers().next().unwrap());
        assert_eq!(LockKey::from_transaction(&transaction).unwrap(), vec![serial_number, sender]);

        // A public fee from the same address: the key is taken once.
        let transaction = sample_transfer_public_transaction(false, rng);
        assert!(transaction.fee_transition().unwrap().is_fee_public());
        assert_eq!(LockKey::from_transaction(&transaction).unwrap(), vec![sender]);
    }
}
