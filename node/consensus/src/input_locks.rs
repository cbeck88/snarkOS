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

use snarkvm::{ledger::Transaction, prelude::*};

use anyhow::{Result, bail, ensure};
use std::collections::HashMap;

/// A lock key of a transaction: the input its fee spends, visible in the plaintext.
///
/// At most one pending transaction per key is admitted to the memory pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LockKey<N: Network> {
    /// The payer of a public fee.
    Payer(Address<N>),
    /// The serial number of a record consumed by a private fee, or by a transaction without a fee.
    SerialNumber(Field<N>),
}

impl<N: Network> LockKey<N> {
    /// Returns the lock keys of the given transaction.
    ///
    /// The keys of a transaction without a fee are the serial numbers of the records it consumes; whether
    /// it is exempt from the fee is left to the VM's full check. One that consumes no record is refused.
    // TODO: widen the key set to every public address the execution debits (03-input-locks, Part 2).
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

/// The lock keys of the transactions admitted to the memory pool and not yet settled in a block.
#[derive(Clone, Debug)]
pub struct InputLocks<N: Network> {
    /// The pending keys, each with the transaction holding it.
    keys: HashMap<LockKey<N>, N::TransactionID>,
    /// The keys and admission block height of each pending transaction.
    entries: HashMap<N::TransactionID, (Vec<LockKey<N>>, u32)>,
    /// The block height of the last expiry run, if any.
    last_expiry_height: Option<u32>,
}

impl<N: Network> Default for InputLocks<N> {
    fn default() -> Self {
        Self { keys: Default::default(), entries: Default::default(), last_expiry_height: None }
    }
}

impl<N: Network> InputLocks<N> {
    /// Returns the number of pending transactions.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no transaction holds a lock.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns `true` if the given transaction holds a lock.
    pub fn contains(&self, transaction_id: &N::TransactionID) -> bool {
        self.entries.contains_key(transaction_id)
    }

    /// Returns `true` if the given key is pending.
    pub fn is_pending(&self, key: &LockKey<N>) -> bool {
        self.keys.contains_key(key)
    }

    /// Returns the transactions holding any of the given keys, each once.
    pub fn holders(&self, keys: &[LockKey<N>]) -> Vec<N::TransactionID> {
        let mut holders = Vec::with_capacity(keys.len());
        for holder in keys.iter().filter_map(|key| self.keys.get(key)) {
            if !holders.contains(holder) {
                holders.push(*holder);
            }
        }
        holders
    }

    /// Ensures none of the given keys is pending.
    pub fn check(&self, keys: &[LockKey<N>]) -> Result<()> {
        if let Some(key) = keys.iter().find(|key| self.is_pending(key)) {
            bail!("Lock key '{key:?}' is already pending in the memory pool");
        }
        Ok(())
    }

    /// Marks the given keys pending for the given transaction, admitted at the given block height.
    pub fn insert(&mut self, transaction_id: N::TransactionID, keys: Vec<LockKey<N>>, height: u32) -> Result<()> {
        ensure!(!self.contains(&transaction_id), "Transaction '{transaction_id}' already holds a lock");
        self.check(&keys)?;
        for key in &keys {
            self.keys.insert(*key, transaction_id);
        }
        self.entries.insert(transaction_id, (keys, height));
        Ok(())
    }

    /// Clears the keys of the given transaction, returning `true` if it held any.
    pub fn remove(&mut self, transaction_id: &N::TransactionID) -> bool {
        let Some((keys, _)) = self.entries.remove(transaction_id) else { return false };
        for key in keys {
            self.keys.remove(&key);
        }
        true
    }

    /// Clears the keys of the transactions admitted at or before `height - max_age`, except those for
    /// which `is_queued` holds: a transaction still in the memory pool's queue has not reached the BFT
    /// yet, so its lock is not stale however long it waits.
    pub fn expire(&mut self, height: u32, max_age: u32, is_queued: impl Fn(&N::TransactionID) -> bool) {
        self.last_expiry_height = Some(height);
        let Some(cutoff) = height.checked_sub(max_age) else { return };
        let stale = self
            .entries
            .iter()
            .filter(|(id, (_, h))| *h <= cutoff && !is_queued(id))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for transaction_id in stale {
            self.remove(&transaction_id);
        }
    }

    /// Runs [`Self::expire`] if the height moved since the last run, so that it is O(1) otherwise.
    pub fn expire_if_height_moved(&mut self, height: u32, max_age: u32, is_queued: impl Fn(&N::TransactionID) -> bool) {
        if self.last_expiry_height != Some(height) {
            self.expire(height, max_age, is_queued);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm::{
        algorithms::snark::varuna::VarunaVersion,
        circuit::AleoV0,
        ledger::{
            query::Query,
            store::{BlockStore, helpers::memory::BlockMemory},
            test_helpers::{
                sample_deployment_transaction,
                sample_execution,
                sample_execution_transaction_with_fee,
                sample_genesis_block_and_components,
            },
        },
        prelude::{MainnetV0, TestRng},
        synthesizer::Process,
    };

    use aleo_std::StorageMode;

    type CurrentNetwork = MainnetV0;

    fn sample_id(rng: &mut TestRng) -> <CurrentNetwork as Network>::TransactionID {
        Field::<CurrentNetwork>::rand(rng).into()
    }

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

    #[test]
    fn one_pending_transaction_per_key() {
        let rng = &mut TestRng::default();
        let mut locks = InputLocks::<CurrentNetwork>::default();

        // One per payer address.
        let payer = LockKey::Payer(Address::rand(rng));
        let first = sample_id(rng);
        locks.insert(first, vec![payer], 0).unwrap();
        assert!(locks.is_pending(&payer));
        assert!(locks.check(&[payer]).is_err());
        assert!(locks.insert(sample_id(rng), vec![payer], 0).is_err());
        // Another payer is independent.
        locks.insert(sample_id(rng), vec![LockKey::Payer(Address::rand(rng))], 0).unwrap();

        // One per serial number.
        let serial_number = LockKey::SerialNumber(Field::rand(rng));
        locks.insert(sample_id(rng), vec![serial_number], 0).unwrap();
        assert!(locks.insert(sample_id(rng), vec![serial_number], 0).is_err());
        // A transaction with several keys is refused if any one of them is pending, and takes none.
        let other = LockKey::SerialNumber(Field::rand(rng));
        assert!(locks.insert(sample_id(rng), vec![other, serial_number], 0).is_err());
        assert!(!locks.is_pending(&other));
        assert_eq!(locks.len(), 3);

        // A transaction cannot hold a lock twice.
        assert!(locks.insert(first, vec![other], 0).is_err());
        assert!(!locks.is_pending(&other));
    }

    #[test]
    fn keys_are_cleared_on_remove() {
        let rng = &mut TestRng::default();
        let mut locks = InputLocks::<CurrentNetwork>::default();
        let payer = LockKey::Payer(Address::rand(rng));
        let serial_number = LockKey::SerialNumber(Field::rand(rng));

        // Eviction, a failed worker check and block advance all clear the keys through `remove`.
        let id = sample_id(rng);
        locks.insert(id, vec![payer, serial_number], 0).unwrap();
        assert!(locks.remove(&id));
        assert!(!locks.contains(&id) && !locks.is_pending(&payer) && !locks.is_pending(&serial_number));
        assert!(!locks.remove(&id));

        // The keys are free again.
        locks.insert(sample_id(rng), vec![payer], 0).unwrap();
        locks.insert(sample_id(rng), vec![serial_number], 0).unwrap();
        assert_eq!(locks.len(), 2);
    }

    #[test]
    fn keys_expire_by_height() {
        let rng = &mut TestRng::default();
        let mut locks = InputLocks::<CurrentNetwork>::default();
        let old = LockKey::Payer(Address::rand(rng));
        let recent = LockKey::Payer(Address::rand(rng));
        locks.insert(sample_id(rng), vec![old], 10).unwrap();
        locks.insert(sample_id(rng), vec![recent], 11).unwrap();

        // Nothing is old enough yet (and the height does not underflow).
        locks.expire(5, 100, |_| false);
        locks.expire(109, 100, |_| false);
        assert_eq!(locks.len(), 2);

        // At height 110, the lock taken at height 10 is stale.
        locks.expire(110, 100, |_| false);
        assert!(!locks.is_pending(&old));
        assert!(locks.is_pending(&recent));
        locks.insert(sample_id(rng), vec![old], 110).unwrap();
    }

    #[test]
    fn expiry_skips_queued_transactions_and_runs_once_per_height() {
        let rng = &mut TestRng::default();
        let mut locks = InputLocks::<CurrentNetwork>::default();
        let (queued_key, settled_key) = (LockKey::Payer(Address::rand(rng)), LockKey::Payer(Address::rand(rng)));
        let (queued, settled) = (sample_id(rng), sample_id(rng));
        locks.insert(queued, vec![queued_key], 10).unwrap();
        locks.insert(settled, vec![settled_key], 10).unwrap();

        // A transaction still in the queue keeps its lock past the maximum age.
        locks.expire(110, 100, |id| *id == queued);
        assert!(locks.is_pending(&queued_key) && !locks.is_pending(&settled_key));

        // At the same height, expiry does not run again, even though the transaction left the queue.
        locks.expire_if_height_moved(110, 100, |_| false);
        assert!(locks.is_pending(&queued_key));
        // Once the height moves, it does.
        locks.expire_if_height_moved(111, 100, |_| false);
        assert!(!locks.is_pending(&queued_key) && locks.is_empty());
    }

    #[test]
    fn holders_of_keys() {
        let rng = &mut TestRng::default();
        let mut locks = InputLocks::<CurrentNetwork>::default();
        let (payer, serial_number) = (LockKey::Payer(Address::rand(rng)), LockKey::SerialNumber(Field::rand(rng)));
        let id = sample_id(rng);
        locks.insert(id, vec![payer, serial_number], 0).unwrap();
        assert_eq!(locks.holders(&[payer, serial_number, LockKey::Payer(Address::rand(rng))]), vec![id]);
        assert!(locks.holders(&[LockKey::SerialNumber(Field::rand(rng))]).is_empty());
    }

    #[test]
    fn lock_keys_of_transactions_with_a_fee() {
        let rng = &mut TestRng::default();

        // A public fee locks its payer.
        let transaction = sample_execution_transaction_with_fee(false, rng, 0);
        let fee = transaction.fee_transition().unwrap();
        assert_eq!(LockKey::from_transaction(&transaction).unwrap(), vec![LockKey::Payer(fee.payer().unwrap())]);

        // A private fee locks the serial number of its record.
        let transaction = sample_execution_transaction_with_fee(true, rng, 0);
        let fee = transaction.fee_transition().unwrap();
        let serial_numbers = fee.serial_numbers().map(|sn| LockKey::SerialNumber(*sn)).collect::<Vec<_>>();
        assert_eq!(serial_numbers.len(), 1);
        assert_eq!(LockKey::from_transaction(&transaction).unwrap(), serial_numbers);

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
}
