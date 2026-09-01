//! Data availability: the per-batch blob that makes the escape hatch real.
//!
//! For the system to be genuinely non-custodial, a user must be able to
//! reconstruct their account state and exit **without the operator** — using
//! only data posted publicly (on-chain). That data is the [`DaBlob`]: for each
//! account a batch changed, its new contents. Apply the blobs in order
//! ([`reconstruct`]) and you have the full account set behind the committed
//! root, from which anyone can build the Merkle proof an escape withdrawal needs.
//!
//! v0 carries full account contents per changed account; a production system
//! compresses to minimal deltas (Lighter's "Account Delta Tree") and posts them
//! as Ethereum blobs. The shape — "changed accounts per batch, replayed to
//! reconstruct" — is the same.

use std::collections::BTreeMap;

use crate::account::Account;
use crate::id::AccountId;

/// The data-availability blob for one batch: the new contents of every account
/// the batch changed (`None` = the account was pruned to empty). Posted with the
/// batch so account state can be reconstructed from public data alone.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DaBlob {
    pub accounts: Vec<(AccountId, Option<Account>)>,
}

/// Reconstruct the full account set from an ordered sequence of DA blobs — what
/// a user does from on-chain data to prove their balance for an escape exit.
/// Later blobs overwrite earlier ones (last write wins); `None` removes.
pub fn reconstruct(blobs: &[DaBlob]) -> BTreeMap<AccountId, Account> {
    let mut accounts = BTreeMap::new();
    for blob in blobs {
        for (id, contents) in &blob.accounts {
            match contents {
                Some(acc) => {
                    accounts.insert(*id, acc.clone());
                }
                None => {
                    accounts.remove(id);
                }
            }
        }
    }
    accounts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Amount, AssetId};
    use uuid::Uuid;

    fn acct(i: u128) -> AccountId {
        AccountId(Uuid::from_u128(i))
    }

    #[test]
    fn later_blobs_overwrite_and_none_removes() {
        let mut a = Account::new();
        a.credit(AssetId(0), Amount(100)).unwrap();
        let mut a2 = Account::new();
        a2.credit(AssetId(0), Amount(40)).unwrap();

        let blobs = vec![
            DaBlob {
                accounts: vec![(acct(1), Some(a)), (acct(2), Some(a2.clone()))],
            },
            // account 1 updated, account 2 emptied
            DaBlob {
                accounts: vec![(acct(1), Some(a2.clone())), (acct(2), None)],
            },
        ];
        let recon = reconstruct(&blobs);
        assert_eq!(recon.get(&acct(1)), Some(&a2));
        assert_eq!(recon.get(&acct(2)), None);
    }
}
