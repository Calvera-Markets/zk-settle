//! The transaction-source seam and a synthetic source.
//!
//! [`TxSource`] is what the replay loop ([`crate::engine::Engine`]) pulls
//! batches from. v0 ships [`SyntheticSource`] (scripted batches for tests and
//! demos). The real implementation is the **off-path tailer**
//! (`../docs/zk-validity-feasibility.md` §5): it reads the sequencer's committed
//! log, decodes each `Envelope::Order` into a [`crate::tx::Tx`] (a deposit /
//! withdraw, or a book-produced fill → `Trade`), groups them into batches, and
//! yields them here — with no change to the engine or the state machine.

use std::collections::VecDeque;

use crate::tx::Tx;

/// A source of transaction batches. A batch is the unit the engine clears and
/// proves together (the analogue of a Lighter "block"/"segment").
pub trait TxSource {
    /// The next batch, or `None` when the source is exhausted.
    fn next_batch(&mut self) -> Option<Vec<Tx>>;
}

/// A scripted, in-memory source: yields pre-built batches in order. The stand-in
/// for the committed-log tailer until that adapter exists.
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
