//! Where [`crate::engine::Engine`] gets batches of [`crate::tx::Tx`].
//!
//! [`SyntheticSource`] is an in-memory queue of scripted batches (tests and
//! demos). A live adapter would pull deposits, withdraws, and fills from the
//! sequencer log and implement the same [`TxSource`] trait.

use std::collections::VecDeque;

use crate::tx::Tx;

/// A source of transaction batches. The engine clears and proves one batch
/// at a time.
pub trait TxSource {
    /// The next batch, or `None` when the source is exhausted.
    fn next_batch(&mut self) -> Option<Vec<Tx>>;
}

/// Scripted in-memory source: yields pre-built batches in order.
#[derive(Debug, Clone, Default)]
pub struct SyntheticSource {
    batches: VecDeque<Vec<Tx>>,
}

impl SyntheticSource {
    pub fn new(batches: Vec<Vec<Tx>>) -> Self {
        Self {
            batches: batches.into(),
        }
    }

    /// Append a batch to the back of the queue.
    pub fn push(&mut self, batch: Vec<Tx>) {
        self.batches.push_back(batch);
    }

    /// Batches still pending.
    pub fn remaining(&self) -> usize {
        self.batches.len()
    }
}

impl TxSource for SyntheticSource {
    fn next_batch(&mut self) -> Option<Vec<Tx>> {
        self.batches.pop_front()
    }
}
