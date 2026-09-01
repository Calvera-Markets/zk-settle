//! The state commitment: a sparse Merkle tree over accounts, keyed by
//! [`AccountId`], producing a [`Hash`] root.
//!
//! The root is the cryptographic commitment to the entire account state — what
//! a validity proof will attest to and what on-chain settlement would store.
//! v0 uses a plain SHA-256 [`Hasher`] ([`hash_plain::Sha256Hasher`]); a
//! SNARK-friendly Poseidon2 impl drops in later behind the same trait.
//!
//! ## Why a sparse Merkle tree
//!
//! Keying by the account's 128-bit UUID gives a fixed-depth (128) tree where
//! every empty subtree collapses to a precomputed default hash, so only
//! non-empty nodes are stored. Two properties matter:
//!
//! - **Canonical:** an empty account and an absent account hash identically
//!   (the [`crate::account::Account`] prunes zero balances, and the state
//!   machine prunes empty accounts), so the root depends only on real holdings,
//!   never on history.
//! - **Incremental:** a changed account re-hashes only the 128 nodes on its
//!   root-to-leaf path, driven by [`crate::state::StateDelta`]. The
//!   `from_state` rebuild is the cross-check.

pub mod hash_plain;
#[cfg(feature = "poseidon2")]
pub mod hash_poseidon2;

use std::collections::BTreeMap;

use crate::account::Account;
use crate::id::{AccountId, Amount, AssetId, L1Address};
use crate::state::{State, StateDelta};

/// A 32-byte commitment hash.
pub type Hash = [u8; 32];

/// Depth of the tree = bits in an [`AccountId`] (UUID is 128-bit). Level 0 is
/// the root; level `DEPTH` holds the leaves.
const DEPTH: u8 = 128;

/// Canonical account-leaf encoding version. Bump on any layout change so a
/// stale encoding can never silently produce a matching root.
/// v2 appends the account's registered trading key; v3 appends its per-order
/// fill accounting; v4 appends the L1 owner (see `canonical_encode`).
const LEAF_VERSION: u8 = 4;

/// Canonical order-encoding version (for [`order_id`]).
const ORDER_VERSION: u8 = 1;

/// Version byte for the matcher-signed fill message (see [`encode_matcher_msg`]).
const MATCHER_MSG_VERSION: u8 = 1;

/// Version byte for a withdrawal leaf (see [`encode_withdrawal`]). v2 uses a
/// 32-byte L1 owner (Solana pubkey) in a fixed 65-byte encoding.
const WITHDRAWAL_VERSION: u8 = 2;

/// The commitment hash function. Leaf and node hashing are separate (and the
/// impl domain-separates them) so a leaf can never be reinterpreted as a node.
pub trait Hasher {
    fn hash_leaf(&self, data: &[u8]) -> Hash;
    fn hash_node(&self, left: &Hash, right: &Hash) -> Hash;
}

/// Canonical, versioned byte encoding of an account for leaf hashing.
///
/// Deterministic by construction: balances and positions are emitted in
/// key-sorted order (the account stores them in `BTreeMap`s), every field is
/// fixed-width little-endian, and a leading version byte guards the layout.
/// This is the only place an [`Account`] becomes bytes for the commitment.
pub fn canonical_encode(account: &Account) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(LEAF_VERSION);

    let balances: Vec<_> = account.balances().collect();
    out.extend_from_slice(&(balances.len() as u32).to_le_bytes());
    for (asset, amount) in balances {
        out.extend_from_slice(&asset.0.to_le_bytes()); // u32
        out.extend_from_slice(&amount.to_le_bytes()); // i128 (16 bytes)
    }

    let positions: Vec<_> = account.positions().collect();
    out.extend_from_slice(&(positions.len() as u32).to_le_bytes());
    for (id, p) in positions {
        out.extend_from_slice(&id.0.to_le_bytes()); // u64
        out.extend_from_slice(&p.signed_size.to_le_bytes()); // i128
        out.extend_from_slice(&p.entry_price.to_le_bytes()); // i128
        match p.cached_funding_idx {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_le_bytes());
            }
            None => out.push(0),
        }
    }

    // Registered trading key (presence flag + 32 bytes). v2 addition.
    match account.trading_key() {
        Some(k) => {
            out.push(1);
            out.extend_from_slice(&k.0);
        }
        None => out.push(0),
    }

    // Per-order fill accounting (id-sorted). v3 addition.
    let fills: Vec<_> = account.order_fills().collect();
    out.extend_from_slice(&(fills.len() as u32).to_le_bytes());
    for (id, filled) in fills {
        out.extend_from_slice(id); // 32-byte order id
        out.extend_from_slice(&filled.to_le_bytes()); // i128
    }

    // L1 owner (presence flag + 32 bytes). v4 addition, after fills.
    match account.l1_owner() {
        Some(o) => {
            out.push(1);
            out.extend_from_slice(&o.0);
        }
        None => out.push(0),
    }
    out
}

/// Canonical, versioned byte encoding of an [`Order`] — the message a user's
/// trading key signs and the preimage of the order's identity. Fixed-width
/// little-endian, version-guarded, same discipline as `canonical_encode`.
pub fn encode_order(order: &crate::auth::Order) -> Vec<u8> {
    use crate::auth::Side;
    let mut out = Vec::with_capacity(1 + 16 + 16 + 1 + 16 + 16 + 8 + 8);
    out.push(ORDER_VERSION);
    out.extend_from_slice(&order.account.0.as_u128().to_le_bytes()); // u128
    out.extend_from_slice(&order.market.0.as_u128().to_le_bytes()); // u128
    out.push(match order.side {
        Side::Buy => 0,
        Side::Sell => 1,
    });
    out.extend_from_slice(&order.base_amount.to_le_bytes()); // i128
    out.extend_from_slice(&order.limit_price.to_le_bytes()); // i128
    out.extend_from_slice(&order.expiry.to_le_bytes()); // u64
    out.extend_from_slice(&order.salt.to_le_bytes()); // u64
    out
}

/// The order's stable identity (its key in the fill-accounting map, and later the
/// orders tree): a fixed **SHA-256** of `encode_order`. Fixed rather than the
/// generic commitment `Hasher` so [`crate::state::State`] can compute it without
/// carrying a hasher type; it is only an addressing id, not a structural node
/// hash. `salt` makes it unique for otherwise-identical orders.
pub fn order_id(order: &crate::auth::Order) -> Hash {
    hash_plain::Sha256Hasher.hash_leaf(&encode_order(order))
}

/// Canonical bytes the **matcher** signs to authorize a fill: it binds the two
/// order identities and the exact fill (market, parties, amounts). Signing this
/// is the operator attesting "our engine paired these two orders into this fill."
pub fn encode_matcher_msg(
    market: crate::id::MarketId,
    buy_id: &Hash,
    sell_id: &Hash,
    fill: &crate::settlement::Fill,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + 16 + 16 + 16 + 16 + 16);
    out.push(MATCHER_MSG_VERSION);
    out.extend_from_slice(buy_id);
    out.extend_from_slice(sell_id);
    out.extend_from_slice(&market.0.as_u128().to_le_bytes());
    out.extend_from_slice(&fill.buyer.0.as_u128().to_le_bytes());
    out.extend_from_slice(&fill.seller.0.as_u128().to_le_bytes());
    out.extend_from_slice(&fill.base_amount.to_le_bytes());
    out.extend_from_slice(&fill.quote_amount.to_le_bytes());
    out
}

// ----- Withdrawals commitment (a small dense Merkle tree over a batch's payouts)
//
// A settled batch commits ONE `withdrawals_root` over its withdrawal messages;
// users then *claim* asynchronously with a leaf + inclusion path (see
// `MockSettlementContract::claim`). The leaf binds `(batch_seq, index)` so it is
// globally unique — that uniqueness is what the claim nullifier keys on, and it
// stops two identical `(owner, asset, amount)` payouts from colliding.

/// Canonical, versioned encoding of one withdrawal leaf. Fixed width **65
/// bytes**: version `0x02`, `batch_seq` u64 LE, `index` u32 LE, owner 32,
/// asset u32 LE, amount i128 LE.
pub fn encode_withdrawal(
    batch_seq: u64,
    index: u32,
    owner: L1Address,
    asset: AssetId,
    amount: Amount,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(WITHDRAWAL_VERSION);
    out.extend_from_slice(&batch_seq.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&owner.0);
    out.extend_from_slice(&asset.0.to_le_bytes());
    out.extend_from_slice(&amount.to_le_bytes());
    debug_assert_eq!(out.len(), 65);
    out
}

/// The leaf hash for a withdrawal — also serves as its **nullifier** (globally
/// unique via `batch_seq` + `index`).
pub fn withdrawal_leaf<H: Hasher>(
    hasher: &H,
    batch_seq: u64,
    index: u32,
    owner: L1Address,
    asset: AssetId,
    amount: Amount,
) -> Hash {
    hasher.hash_leaf(&encode_withdrawal(batch_seq, index, owner, asset, amount))
}

/// Pad a leaf level to the next power of two with the empty-leaf hash.
fn pad_pow2<H: Hasher>(hasher: &H, mut leaves: Vec<Hash>) -> Vec<Hash> {
    let empty = hasher.hash_leaf(&[]);
    if leaves.is_empty() {
        leaves.push(empty);
    }
    while !leaves.len().is_power_of_two() {
        leaves.push(empty);
    }
    leaves
}

/// The Merkle root over a batch's withdrawal leaves (dense, padded to a power of
/// two). `entries` are `(owner, asset, amount)` in message order; the index is
/// the position, folded into the leaf.
pub fn withdrawals_root<H: Hasher>(
    hasher: &H,
    batch_seq: u64,
    entries: &[(L1Address, AssetId, Amount)],
) -> Hash {
    let leaves: Vec<Hash> = entries
        .iter()
        .enumerate()
        .map(|(i, (o, a, amt))| withdrawal_leaf(hasher, batch_seq, i as u32, *o, *a, *amt))
        .collect();
    let mut level = pad_pow2(hasher, leaves);
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| hasher.hash_node(&c[0], &c[1]))
            .collect();
    }
    level[0]
}

/// The inclusion path (siblings, leaf→root) for the withdrawal at `index`.
pub fn withdrawal_proof<H: Hasher>(
    hasher: &H,
    batch_seq: u64,
    entries: &[(L1Address, AssetId, Amount)],
    index: usize,
) -> Vec<Hash> {
    let leaves: Vec<Hash> = entries
        .iter()
        .enumerate()
        .map(|(i, (o, a, amt))| withdrawal_leaf(hasher, batch_seq, i as u32, *o, *a, *amt))
        .collect();
    let mut level = pad_pow2(hasher, leaves);
    let mut idx = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        siblings.push(level[idx ^ 1]);
        level = level
            .chunks(2)
            .map(|c| hasher.hash_node(&c[0], &c[1]))
            .collect();
        idx /= 2;
    }
    siblings
}

/// Fold a withdrawal leaf up its `siblings` and check it reproduces `root`. This
/// is the check a claim runs against the committed `withdrawals_root`.
#[allow(clippy::too_many_arguments)]
pub fn verify_withdrawal<H: Hasher>(
    hasher: &H,
    root: Hash,
    batch_seq: u64,
    index: u32,
    owner: L1Address,
    asset: AssetId,
    amount: Amount,
    siblings: &[Hash],
) -> bool {
    let mut cur = withdrawal_leaf(hasher, batch_seq, index, owner, asset, amount);
    let mut idx = index as usize;
    for sib in siblings {
        cur = if idx & 1 == 0 {
            hasher.hash_node(&cur, sib)
        } else {
            hasher.hash_node(sib, &cur)
        };
        idx /= 2;
    }
    cur == root
}

/// One leaf write captured for a witness: the account key, its leaf hash before
/// and after the write, plus the sibling path (leaf → root) **at write time** in
/// a **sparse** encoding.
///
/// The tree is almost entirely empty, so most siblings on a path are the
/// fixed empty-subtree *default* for their level — which a verifier already
/// knows. So we transmit only the **non-default** siblings (`siblings`, in
/// leaf→root order) plus a `sibling_mask` whose bit *step* is set iff the
/// sibling at that step is non-default. The verifier fills the rest from the
/// defaults. With few accounts a path has ~1–3 non-default siblings instead of
/// [`DEPTH`]; the count grows only ~log₂(accounts).
///
/// Chaining these — verifying `prev_leaf + path` against the running root, then
/// advancing with `new_leaf + path` — reconstructs the whole `prev_root →
/// new_root` transition using only hashes, no tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LeafUpdate {
    pub key: u128,
    pub prev_leaf: Hash,
    pub new_leaf: Hash,
    /// Bit `step` set ⇒ the sibling at that step (leaf→root) is non-default and
    /// present in `siblings`; else it is `defaults[DEPTH - step]`.
    pub sibling_mask: u128,
    /// The non-default siblings only, in leaf→root (step) order.
    pub siblings: Vec<Hash>,
}

/// The leaf hash for an account: the canonical-encoding hash for a non-empty
/// account, or the empty-leaf hash for absent/empty. The single definition of
/// "account → leaf", shared by [`StateTree`] and any verifier that re-derives
/// leaves from reconstructed contents (the executing prover / zkVM guest).
pub fn leaf_hash<H: Hasher>(hasher: &H, account: Option<&Account>) -> Hash {
    match account {
        Some(a) if !a.is_empty() => hasher.hash_leaf(&canonical_encode(a)),
        _ => hasher.hash_leaf(&[]),
    }
}

/// The per-level empty-subtree default hashes (`len == DEPTH + 1`). A verifier
/// that has no tree (the prover / zkVM guest / the escape-hatch path) computes
/// these once from the hash function to fill in a sparse proof's omitted
/// default siblings.
pub fn default_hashes<H: Hasher>(hasher: &H) -> Vec<Hash> {
    let mut d = vec![[0u8; 32]; DEPTH as usize + 1];
    d[DEPTH as usize] = hasher.hash_leaf(&[]); // empty-leaf hash
    for level in (0..DEPTH as usize).rev() {
        d[level] = hasher.hash_node(&d[level + 1], &d[level + 1]);
    }
    d
}

/// Fold a leaf up through its (sparse) sibling path to the root it implies.
/// `defaults` is [`default_hashes`]; omitted siblings (mask bit clear) use the
/// level default. The inverse of the tree's own path recomputation; used to
/// verify witnesses without a tree. A malformed proof (mask claims more
/// siblings than provided) yields a wrong root — a clean verification failure,
/// not a panic.
pub fn root_from_path<H: Hasher>(
    hasher: &H,
    defaults: &[Hash],
    key: u128,
    leaf: Hash,
    sibling_mask: u128,
    siblings: &[Hash],
) -> Hash {
    let mut node = leaf;
    let mut index = key;
    let mut next = 0;
    for step in 0..DEPTH {
        let level = (DEPTH - step) as usize; // tree level of this step's sibling
        let sib = if (sibling_mask >> step) & 1 == 1 {
            let s = siblings.get(next).copied().unwrap_or(defaults[level]);
            next += 1;
            s
        } else {
            defaults[level]
        };
        node = if index & 1 == 0 {
            hasher.hash_node(&node, &sib)
        } else {
            hasher.hash_node(&sib, &node)
        };
        index >>= 1;
    }
    node
}

/// A sparse Merkle tree committing the account set.
///
/// Stores only non-default nodes; empty subtrees resolve to precomputed
/// `defaults[level]`. `root()` is derived by structured traversal, so the
/// internal node map's iteration order never affects the commitment.
///
/// ## Design notes
///
/// - **Key = raw 128-bit UUID.** The tree is keyed directly on the account's
///   UUID (`AccountId::0.as_u128()`), which gives a clean fixed depth of
///   [`DEPTH`] with no key-hashing step. If account ids ever exceed 128 bits, or
///   we want hash-prefixed keys (e.g. to defend against adversarial key
///   clustering), that is a localized change in [`StateTree::update_account`]
///   (and `DEPTH`) — nothing else depends on the key derivation.
/// - **`nodes` is a `BTreeMap`, not a `HashMap`.** Root derivation never
///   iterates `nodes` (it walks the tree structurally via `get_node`), so
///   iteration order could not affect the commitment regardless. It is kept
///   ordered purely to stay consistent with the crate's determinism discipline
///   ("ordered containers for anything near the commitment").
#[derive(Debug, Clone)]
pub struct StateTree<H: Hasher> {
    hasher: H,
    /// `defaults[l]` = hash of a fully-empty subtree rooted at level `l`.
    /// Length `DEPTH + 1`.
    defaults: Vec<Hash>,
    /// Non-default nodes, keyed by `(level, index)`. Leaf level is `DEPTH`,
    /// index is the account's 128-bit key (at shallower levels, key >> (DEPTH-level)).
    nodes: BTreeMap<(u8, u128), Hash>,
}

impl<H: Hasher> StateTree<H> {
    /// An empty tree (all accounts absent).
    pub fn new(hasher: H) -> Self {
        let defaults = default_hashes(&hasher);
        Self {
            hasher,
            defaults,
            nodes: BTreeMap::new(),
        }
    }

    /// Build a tree from scratch over a full [`State`]. Used as the cross-check
    /// against incremental [`Self::apply_delta`].
    pub fn from_state(hasher: H, state: &State) -> Self {
        Self::from_accounts(hasher, state.accounts())
    }

    /// Build a tree from a bare account set. This is what a user does when
    /// reconstructing from DA blobs (see [`crate::da`]) — they have accounts, not
    /// a full [`State`] — to produce the inclusion proof an escape exit needs.
    pub fn from_accounts<'a, I>(hasher: H, accounts: I) -> Self
    where
        I: IntoIterator<Item = (&'a AccountId, &'a Account)>,
    {
        let mut tree = Self::new(hasher);
        for (id, account) in accounts {
            tree.update_account(*id, Some(account));
        }
        tree
    }

    /// The state-root commitment.
    pub fn root(&self) -> Hash {
        self.get_node(0, 0)
    }

    /// Apply the accounts changed by a [`StateDelta`], reading current values
    /// from `state` (an account pruned to absence updates to the empty leaf).
    pub fn apply_delta(&mut self, state: &State, delta: &StateDelta) {
        for id in &delta.changed {
            self.update_account(*id, state.account(*id));
        }
    }

    /// Re-hash one account's leaf and the path up to the root.
    pub fn update_account(&mut self, id: AccountId, account: Option<&Account>) {
        let leaf = self.leaf_of(account);
        self.write_leaf(id.0.as_u128(), leaf);
    }

    /// Like [`Self::update_account`], but returns the [`LeafUpdate`] (prev/new
    /// leaf + sibling path) needed to build a witness.
    pub fn update_account_proved(
        &mut self,
        id: AccountId,
        account: Option<&Account>,
    ) -> LeafUpdate {
        let key = id.0.as_u128();
        let new_leaf = self.leaf_of(account);
        let (prev_leaf, sibling_mask, siblings) = self.write_leaf(key, new_leaf);
        LeafUpdate {
            key,
            prev_leaf,
            new_leaf,
            sibling_mask,
            siblings,
        }
    }

    /// Apply a [`StateDelta`] and return the per-account [`LeafUpdate`]s, in the
    /// order applied — the witness fragment for this transition.
    pub fn apply_delta_proved(&mut self, state: &State, delta: &StateDelta) -> Vec<LeafUpdate> {
        delta
            .changed
            .iter()
            .map(|id| self.update_account_proved(*id, state.account(*id)))
            .collect()
    }

    /// A sparse inclusion proof for `id`'s current leaf: `(sibling_mask,
    /// non-default siblings)`, in the same encoding as [`LeafUpdate`]. A user
    /// reconstructs this (in a real system, from the DA blobs) and feeds it to
    /// [`root_from_path`] to claim funds from the settlement contract.
    pub fn prove(&self, id: AccountId) -> (u128, Vec<Hash>) {
        let mut mask = 0u128;
        let mut siblings = Vec::new();
        let mut level = DEPTH;
        let mut index = id.0.as_u128();
        let mut step = 0;
        while level > 0 {
            let sib = self.get_node(level, index ^ 1);
            if sib != self.defaults[level as usize] {
                mask |= 1u128 << step;
                siblings.push(sib);
            }
            index >>= 1;
            level -= 1;
            step += 1;
        }
        (mask, siblings)
    }

    /// The leaf hash for an account (the empty-leaf default for absent/empty).
    fn leaf_of(&self, account: Option<&Account>) -> Hash {
        leaf_hash(&self.hasher, account)
    }

    /// Write `new_leaf` at `key`, recompute the path to the root, and return the
    /// previous leaf hash plus the sibling path (leaf → root) captured at write
    /// time.
    fn write_leaf(&mut self, key: u128, new_leaf: Hash) -> (Hash, u128, Vec<Hash>) {
        let prev_leaf = self.get_node(DEPTH, key);
        self.set_node(DEPTH, key, new_leaf);

        // Capture the path sparsely: record only siblings that differ from the
        // level default, with a bitmask of which steps are present.
        let mut mask = 0u128;
        let mut siblings = Vec::new();
        let mut level = DEPTH;
        let mut index = key;
        let mut step = 0;
        while level > 0 {
            let sib = self.get_node(level, index ^ 1);
            if sib != self.defaults[level as usize] {
                mask |= 1u128 << step;
                siblings.push(sib);
            }
            let parent_index = index >> 1;
            let left = self.get_node(level, parent_index << 1);
            let right = self.get_node(level, (parent_index << 1) | 1);
            let parent = self.hasher.hash_node(&left, &right);
            self.set_node(level - 1, parent_index, parent);
            level -= 1;
            index = parent_index;
            step += 1;
        }
        (prev_leaf, mask, siblings)
    }

    fn get_node(&self, level: u8, index: u128) -> Hash {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.defaults[level as usize])
    }

    /// Store a node, or drop it if it equals the level default (keeps the tree
    /// sparse and the encoding canonical).
    fn set_node(&mut self, level: u8, index: u128, hash: Hash) {
        if hash == self.defaults[level as usize] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hash_plain::Sha256Hasher;
    use super::*;
    use crate::id::{Amount, AssetId, InstrumentId, MarketId};
    use crate::instrument::{Instrument, SettlementKind};
    use crate::settlement::Fill;
    use crate::tx::Tx;
    use uuid::Uuid;

    const USDC: AssetId = AssetId(0);
    const BTC: AssetId = AssetId(1);

    fn acct(i: u128) -> AccountId {
        AccountId(Uuid::from_u128(i))
    }
    fn owner(n: u8) -> L1Address {
        L1Address([n; 32])
    }
    fn market() -> MarketId {
        MarketId(Uuid::from_u128(0xA1))
    }

    fn state_with_market() -> State {
        let mut s = State::new();
        s.register_market(
            market(),
            Instrument {
                id: InstrumentId(1),
                kind: SettlementKind::SpotSwap,
                base: BTC,
                quote: USDC,
                base_scale: 8,
                quote_scale: 6,
            },
        );
        s
    }

    #[test]
    fn empty_tree_root_is_default() {
        let t = StateTree::new(Sha256Hasher);
        assert_eq!(t.root(), t.defaults[0]);
    }

    #[test]
    fn add_then_remove_returns_to_empty_root() {
        let mut s = state_with_market();
        let mut t = StateTree::new(Sha256Hasher);
        let empty = t.root();

        let d = s
            .apply(&Tx::Deposit {
                account: acct(7),
                asset: USDC,
                amount: Amount(100),
                nonce: 0,
                owner: owner(7),
                trading_key: None,
            })
            .unwrap();
        t.apply_delta(&s, &d);
        assert_ne!(t.root(), empty, "adding an account must change the root");

        let d = s
            .apply(&Tx::Withdraw {
                account: acct(7),
                asset: USDC,
                amount: Amount(100),
            })
            .unwrap();
        t.apply_delta(&s, &d);
        assert_eq!(
            t.root(),
            empty,
            "removing all holdings returns to empty root"
        );
    }

    #[test]
    fn balance_change_changes_root() {
        let mut s = State::new();
        let mut t = StateTree::new(Sha256Hasher);
        let d = s
            .apply(&Tx::Deposit {
                account: acct(7),
                asset: USDC,
                amount: Amount(100),
                nonce: 0,
                owner: owner(7),
                trading_key: None,
            })
            .unwrap();
        t.apply_delta(&s, &d);
        let r1 = t.root();

        let d = s
            .apply(&Tx::Deposit {
                account: acct(7),
                asset: USDC,
                amount: Amount(1),
                nonce: 1,
                owner: owner(7),
                trading_key: None,
            })
            .unwrap();
        t.apply_delta(&s, &d);
        assert_ne!(t.root(), r1);
    }

    #[test]
    fn update_order_independent() {
        // Two distinct accounts, inserted in opposite orders, yield one root.
        let a = acct(1);
        let b = acct(2);
        let mut acc_a = Account::new();
        acc_a.credit(USDC, Amount(10)).unwrap();
        let mut acc_b = Account::new();
        acc_b.credit(BTC, Amount(3)).unwrap();

        let mut t1 = StateTree::new(Sha256Hasher);
        t1.update_account(a, Some(&acc_a));
        t1.update_account(b, Some(&acc_b));

        let mut t2 = StateTree::new(Sha256Hasher);
        t2.update_account(b, Some(&acc_b));
        t2.update_account(a, Some(&acc_a));

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn incremental_matches_rebuild_after_a_trade() {
        let mut s = state_with_market();
        let mut t = StateTree::new(Sha256Hasher);
        for tx in [
            Tx::Deposit {
                account: acct(0xB),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: owner(1),
                trading_key: None,
            },
            Tx::Deposit {
                account: acct(0x5),
                asset: BTC,
                amount: Amount(5),
                nonce: 1,
                owner: owner(2),
                trading_key: None,
            },
            Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: acct(0xB),
                    seller: acct(0x5),
                    base_amount: Amount(2),
                    quote_amount: Amount(400),
                },
                auth: None,
            },
        ] {
            let d = s.apply(&tx).unwrap();
            t.apply_delta(&s, &d);
        }
        let rebuilt = StateTree::from_state(Sha256Hasher, &s);
        assert_eq!(t.root(), rebuilt.root());
    }

    #[test]
    fn registering_a_trading_key_changes_the_leaf() {
        use crate::account::Account;
        use crate::auth::Ed25519PubKey;

        let mut a = Account::new();
        a.credit(USDC, Amount(1000)).unwrap();
        let before = leaf_hash(&Sha256Hasher, Some(&a));

        a.set_trading_key(Ed25519PubKey([7u8; 32])).unwrap();
        let after = leaf_hash(&Sha256Hasher, Some(&a));

        // The committed leaf binds the key: same balances, different key ⇒
        // different leaf (so a swapped/absent key can't hide in the same root).
        assert_ne!(before, after);
    }

    #[test]
    fn binding_an_owner_changes_the_leaf() {
        use crate::account::Account;
        let mut a = Account::new();
        a.credit(USDC, Amount(1000)).unwrap();
        let encoded = canonical_encode(&a);
        assert_eq!(encoded[0], LEAF_VERSION);
        assert_eq!(*encoded.last().unwrap(), 0); // owner flag 0x00
        let before = leaf_hash(&Sha256Hasher, Some(&a));

        a.set_l1_owner(owner(1)).unwrap();
        let encoded = canonical_encode(&a);
        assert_eq!(encoded[0], LEAF_VERSION);
        assert_eq!(encoded[encoded.len() - 33], 1);
        assert_eq!(&encoded[encoded.len() - 32..], &[1u8; 32]);
        let after = leaf_hash(&Sha256Hasher, Some(&a));
        assert_ne!(before, after);
    }

    #[test]
    fn withdrawal_leaf_v2_is_fixed_65_bytes() {
        let bytes = encode_withdrawal(1, 0, owner(1), USDC, Amount(400));
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], WITHDRAWAL_VERSION);
        assert_eq!(&bytes[1..9], &1u64.to_le_bytes());
        assert_eq!(&bytes[9..13], &0u32.to_le_bytes());
        assert_eq!(&bytes[13..45], &[1u8; 32]);
        assert_eq!(&bytes[45..49], &USDC.0.to_le_bytes());
        assert_eq!(&bytes[49..65], &Amount(400).to_le_bytes());
    }

    #[test]
    fn order_hash_is_unique_per_salt() {
        use crate::auth::{Order, Side};

        let base = Order {
            account: acct(0xB),
            market: market(),
            side: Side::Buy,
            base_amount: Amount(5),
            limit_price: Amount(200),
            expiry: 100,
            salt: 1,
        };
        let same = base;
        let diff_salt = Order { salt: 2, ..base };
        let diff_side = Order {
            side: Side::Sell,
            ..base
        };

        assert_eq!(order_id(&base), order_id(&same));
        assert_ne!(order_id(&base), order_id(&diff_salt));
        assert_ne!(order_id(&base), order_id(&diff_side));
    }
}
