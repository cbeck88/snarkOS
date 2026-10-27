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

pub use snarkos_node_bft_events::LockKey;

use snarkvm::prelude::*;

use anyhow::{Result, bail, ensure};
use std::collections::HashMap;

/// A pending transaction's entry in the lock table.
#[derive(Clone, Debug)]
struct LockEntry<N: Network> {
    /// The keys the transaction holds.
    keys: Vec<LockKey<N>>,
    /// The block height at which the keys were taken.
    height: u32,
    /// Whether this validator signed a lock for the transaction. A signed lock is a promise to the
    /// committee, so it is released only when the transaction settles in a block or the lock expires,
    /// never when the transaction leaves this node's memory pool early.
    signed: bool,
}

/// The lock keys of the transactions admitted to the memory pool or lock-signed by this validator,
/// and not yet settled in a block.
///
/// One table serves both: the keys a transaction takes at admission are the same entry its lock
/// signature confirms, so the originator of a lock round holds each key once.
#[derive(Clone, Debug)]
pub struct InputLocks<N: Network> {
    /// The pending keys, each with the transaction holding it.
    keys: HashMap<LockKey<N>, N::TransactionID>,
    /// The entry of each pending transaction.
    entries: HashMap<N::TransactionID, LockEntry<N>>,
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

    /// Returns `true` if no transaction is pending.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns `true` if the given transaction holds a lock.
    pub fn contains(&self, transaction_id: &N::TransactionID) -> bool {
        self.entries.contains_key(transaction_id)
    }

    /// Returns `true` if this validator signed a lock for the given transaction.
    pub fn is_signed(&self, transaction_id: &N::TransactionID) -> bool {
        self.entries.get(transaction_id).is_some_and(|entry| entry.signed)
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

    /// Ensures none of the given keys is pending for a transaction other than the given one.
    pub fn check_for(&self, transaction_id: &N::TransactionID, keys: &[LockKey<N>]) -> Result<()> {
        if let Some((key, holder)) =
            keys.iter().find_map(|key| self.keys.get(key).filter(|holder| *holder != transaction_id).map(|h| (key, h)))
        {
            bail!("Lock key '{key:?}' is already pending for transaction '{holder}'");
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
        self.entries.insert(transaction_id, LockEntry { keys, height, signed: false });
        Ok(())
    }

    /// Records that this validator signed a lock for the given transaction over the given keys, taking
    /// them at the given block height if the transaction does not hold them yet.
    ///
    /// A transaction that already holds the keys (taken at admission) keeps its entry and height: the
    /// signature confirms the same entry rather than taking a second one.
    pub fn sign(&mut self, transaction_id: N::TransactionID, keys: Vec<LockKey<N>>, height: u32) -> Result<()> {
        match self.entries.get_mut(&transaction_id) {
            Some(entry) => {
                ensure!(entry.keys == keys, "Transaction '{transaction_id}' holds a lock over different keys");
                entry.signed = true;
            }
            None => {
                self.check(&keys)?;
                for key in &keys {
                    self.keys.insert(*key, transaction_id);
                }
                self.entries.insert(transaction_id, LockEntry { keys, height, signed: true });
            }
        }
        Ok(())
    }

    /// Clears the keys of the given transaction unless this validator signed a lock for it, returning
    /// `true` if they were cleared.
    ///
    /// This is the release for a transaction leaving the memory pool without a block: eviction, or a
    /// failed check. A signed lock stays until the transaction settles or the lock expires.
    pub fn release(&mut self, transaction_id: &N::TransactionID) -> bool {
        match self.entries.get(transaction_id) {
            Some(entry) if !entry.signed => self.remove(transaction_id),
            _ => false,
        }
    }

    /// Clears the keys of the given transaction, signed or not, returning `true` if it held any.
    ///
    /// This is the release for a transaction that settled in a block, in any status.
    pub fn remove(&mut self, transaction_id: &N::TransactionID) -> bool {
        let Some(entry) = self.entries.remove(transaction_id) else { return false };
        for key in entry.keys {
            self.keys.remove(&key);
        }
        true
    }

    /// Clears the keys of the transactions taken at or before `height - max_age`, except those for
    /// which `is_queued` holds: a transaction still in the memory pool's queue has not reached the BFT
    /// yet, so its lock is not stale however long it waits. A signed lock whose transaction is not
    /// queued on this node expires by age alone.
    pub fn expire(&mut self, height: u32, max_age: u32, is_queued: impl Fn(&N::TransactionID) -> bool) {
        self.last_expiry_height = Some(height);
        let Some(cutoff) = height.checked_sub(max_age) else { return };
        let stale = self
            .entries
            .iter()
            .filter(|(id, entry)| entry.height <= cutoff && !is_queued(id))
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

    type CurrentNetwork = snarkvm::prelude::MainnetV0;

    fn sample_id(rng: &mut TestRng) -> <CurrentNetwork as Network>::TransactionID {
        Field::<CurrentNetwork>::rand(rng).into()
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

        // A key pending for a transaction is not pending "for another" from that transaction's view.
        assert!(locks.check_for(&first, &[payer]).is_ok());
        assert!(locks.check_for(&sample_id(rng), &[payer]).is_err());
    }

    #[test]
    fn keys_are_cleared_on_release_and_remove() {
        let rng = &mut TestRng::default();
        let mut locks = InputLocks::<CurrentNetwork>::default();
        let payer = LockKey::Payer(Address::rand(rng));
        let serial_number = LockKey::SerialNumber(Field::rand(rng));

        // Eviction and a failed worker check clear an unsigned entry through `release`.
        let id = sample_id(rng);
        locks.insert(id, vec![payer, serial_number], 0).unwrap();
        assert!(locks.release(&id));
        assert!(!locks.contains(&id) && !locks.is_pending(&payer) && !locks.is_pending(&serial_number));
        assert!(!locks.release(&id));
        assert!(!locks.remove(&id));

        // The keys are free again; block advance clears through `remove`.
        let id = sample_id(rng);
        locks.insert(id, vec![payer], 0).unwrap();
        locks.insert(sample_id(rng), vec![serial_number], 0).unwrap();
        assert_eq!(locks.len(), 2);
        assert!(locks.remove(&id));
        assert!(!locks.is_pending(&payer));
    }

    #[test]
    fn a_signed_lock_is_released_only_by_a_block_or_expiry() {
        let rng = &mut TestRng::default();
        let mut locks = InputLocks::<CurrentNetwork>::default();
        let payer = LockKey::Payer(Address::rand(rng));

        // Signing a lock for a transaction admitted earlier confirms its entry, keeping its height.
        let admitted = sample_id(rng);
        locks.insert(admitted, vec![payer], 5).unwrap();
        assert!(!locks.is_signed(&admitted));
        locks.sign(admitted, vec![payer], 9).unwrap();
        assert!(locks.is_signed(&admitted) && locks.len() == 1);
        // Over different keys, it is refused.
        assert!(locks.sign(admitted, vec![LockKey::Payer(Address::rand(rng))], 9).is_err());
        // The soft release leaves it in place; a block clears it.
        assert!(!locks.release(&admitted));
        assert!(locks.is_pending(&payer));
        assert!(locks.remove(&admitted));
        assert!(!locks.is_pending(&payer));

        // Signing a lock for a transaction this node never admitted takes the keys at the given height.
        let signed = sample_id(rng);
        locks.sign(signed, vec![payer], 10).unwrap();
        assert!(locks.is_signed(&signed) && locks.is_pending(&payer));
        assert!(locks.sign(sample_id(rng), vec![payer], 10).is_err());
        assert!(!locks.release(&signed));
        // The lock taken at height 10 expires at height 110 with a maximum age of 100.
        locks.expire(109, 100, |_| false);
        assert!(locks.is_pending(&payer));
        locks.expire(110, 100, |_| false);
        assert!(!locks.is_pending(&payer) && !locks.contains(&signed));
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
        let (queued_key, signed_key) = (LockKey::Payer(Address::rand(rng)), LockKey::Payer(Address::rand(rng)));
        let (queued, signed) = (sample_id(rng), sample_id(rng));
        locks.insert(queued, vec![queued_key], 10).unwrap();
        locks.sign(signed, vec![signed_key], 10).unwrap();

        // A transaction still in the queue keeps its lock past the maximum age; a signed lock whose
        // transaction is not queued here expires by age.
        locks.expire(110, 100, |id| *id == queued);
        assert!(locks.is_pending(&queued_key) && !locks.is_pending(&signed_key));

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
}
