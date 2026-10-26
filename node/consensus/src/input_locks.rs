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
    /// The serial number of the record consumed by a private fee.
    SerialNumber(Field<N>),
}

impl<N: Network> LockKey<N> {
    /// Returns the lock keys of the given transaction.
    // TODO: widen the key set to every public address the execution debits (03-input-locks, Part 2).
    pub fn from_transaction(transaction: &Transaction<N>) -> Result<Vec<Self>> {
        let Some(fee) = transaction.fee_transition() else {
            bail!("Transaction '{}' is missing a fee", transaction.id());
        };
        let keys = match (fee.is_fee_public(), fee.payer()) {
            (true, Some(payer)) => vec![Self::Payer(payer)],
            (true, None) => bail!("Transaction '{}' has a public fee without a payer", transaction.id()),
            (false, _) => fee.serial_numbers().map(|serial_number| Self::SerialNumber(*serial_number)).collect(),
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
