//! Data availability blobs for the escape hatch.
//!
//! Each batch posts a [`DaBlob`]: the new contents of every account it changed
//! (`None` means the account was pruned). [`reconstruct`] replays blobs in
//! order (last write wins) so a user can rebuild the account set from public
//! data and prove an escape withdrawal against the committed root.

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
