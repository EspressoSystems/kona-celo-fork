//! Batch Authentication via L1 Event Scanning
//!
//! This module implements event-based batch authentication for the Espresso integration.
//! Instead of relying on an on-chain BatchInbox contract to verify batches, the derivation
//! pipeline scans L1 receipts for `BatchInfoAuthenticated(bytes32 indexed commitment)` events
//! emitted by the `BatchAuthenticator` contract within a lookback window.
//!
//! Two authorization paths are supported:
//! 1. **TEE batcher**: Must have a matching `BatchInfoAuthenticated` event where the commitment
//!    matches the batch content hash. Sender identity is irrelevant.
//! 2. **Fallback batcher**: Authorized via traditional sender address verification against
//!    `fallback_batcher_address`. No auth event needed.
//!
//! When batch auth is not configured (i.e., `batch_authenticator_address` is `None`), the pipeline
//! falls back to the standard OP Stack sender verification.
//!
//! Using event scanning (rather than L1 contract state reads) keeps the derivation pipeline
//! compatible with the op-program fault proof environment, which can only access L1 block headers,
//! transactions, receipts, and blobs — not contract state.

use crate::{ChainProvider, PipelineErrorKind};

use alloc::{collections::BTreeSet, vec::Vec};
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Receipt, TxEnvelope, TxReceipt};
use alloy_primitives::{Address, B256, b256, keccak256};
use kona_protocol::BlockInfo;
use lru::LruCache;

/// Number of L1 blocks before the batch submission to scan for a `BatchInfoAuthenticated` event.
pub(crate) const BATCH_AUTH_LOOKBACK_WINDOW: u64 = 100;

/// The `keccak256("BatchInfoAuthenticated(bytes32)")` event topic.
///
/// This is the event emitted by the `BatchAuthenticator` contract when a batch is authenticated.
/// The first indexed topic is the commitment hash.
pub(crate) const BATCH_INFO_AUTHENTICATED_TOPIC: B256 =
    b256!("ee0d07d204d979d28885955e59a46f754c4db7378b7df1a95123525aac6e3f80");

/// Configuration for event-based batch authentication.
#[derive(Debug, Clone)]
pub struct BatchAuthConfig {
    /// The L1 address of the `BatchAuthenticator` contract.
    pub authenticator_address: Address,
    /// The address of the fallback (non-TEE) batcher. When set, this batcher is authorized
    /// via sender verification without needing an auth event.
    pub fallback_batcher_address: Option<Address>,
}

/// Computes `keccak256(calldata)`, matching the `BatchAuthenticator` contract's calldata batch
/// validation path.
pub(crate) fn compute_calldata_batch_hash(data: &[u8]) -> B256 {
    keccak256(data)
}

/// Computes `keccak256(concat(blob_hashes))`, matching the `BatchAuthenticator` contract's blob
/// batch validation path.
pub(crate) fn compute_blob_batch_hash(blob_hashes: &[B256]) -> B256 {
    let mut concatenated = Vec::with_capacity(32 * blob_hashes.len());
    for hash in blob_hashes {
        concatenated.extend_from_slice(hash.as_slice());
    }
    keccak256(&concatenated)
}

/// Extracts all authenticated batch commitment hashes from a single block's receipts.
///
/// Scans for `BatchInfoAuthenticated` events emitted by `authenticator_addr` in successful
/// receipts. Returns the set of commitment hashes found.
pub(crate) fn collect_auth_events_from_receipts(
    receipts: &[Receipt],
    authenticator_addr: Address,
) -> BTreeSet<B256> {
    let topic0 = BATCH_INFO_AUTHENTICATED_TOPIC;
    let mut result = BTreeSet::new();
    for receipt in receipts {
        if !receipt.status() {
            continue;
        }
        for log in &receipt.logs {
            if log.address != authenticator_addr {
                continue;
            }
            if log.topics().len() >= 2 && log.topics()[0] == topic0 {
                result.insert(log.topics()[1]);
            }
        }
    }
    result
}

/// Scans L1 receipts in the range `[block_ref.number - BATCH_AUTH_LOOKBACK_WINDOW, block_ref.number]`
/// and returns the set of all batch commitment hashes that were authenticated via
/// `BatchInfoAuthenticated` events.
///
/// This is called once per L1 block by the data source, and the returned set is checked
/// against each candidate batch transaction. This avoids rescanning the lookback window
/// for every individual batch transaction.
///
/// Results are cached per block hash in the provided LRU cache. For consecutive L1 blocks
/// the lookback windows overlap by ~99 blocks, so only one new block's receipts need
/// to be fetched on each call. The cache is keyed by block hash (not number) so it is
/// naturally reorg-safe.
pub(crate) async fn collect_authenticated_batches<CP: ChainProvider + Send>(
    provider: &mut CP,
    block_ref: &BlockInfo,
    authenticator_addr: Address,
    cache: &mut LruCache<B256, BTreeSet<B256>>,
) -> Result<BTreeSet<B256>, PipelineErrorKind> {
    let mut all_authenticated = BTreeSet::new();
    let mut current_hash = block_ref.hash;
    let mut current_number = block_ref.number;

    loop {
        // Check cache first
        if let Some(cached) = cache.get(&current_hash) {
            all_authenticated.extend(cached.iter());
        } else {
            // Cache miss: fetch receipts, extract events, cache the result
            let receipts = provider.receipts_by_hash(current_hash).await.map_err(Into::into)?;
            let events = collect_auth_events_from_receipts(&receipts, authenticator_addr);
            all_authenticated.extend(events.iter());
            cache.put(current_hash, events);
        }

        if current_number == 0 || block_ref.number - current_number >= BATCH_AUTH_LOOKBACK_WINDOW {
            break;
        }

        // Walk backward using header to get parent hash
        let header = provider.header_by_hash(current_hash).await.map_err(Into::into)?;
        current_hash = header.parent_hash;
        current_number = current_number.saturating_sub(1);
    }

    Ok(all_authenticated)
}

/// Creates an LRU cache for batch auth events, sized slightly larger than the lookback window
/// to avoid thrashing at the boundary.
pub(crate) fn new_batch_auth_cache() -> LruCache<B256, BTreeSet<B256>> {
    LruCache::new(
        core::num::NonZeroUsize::new((BATCH_AUTH_LOOKBACK_WINDOW as usize) + 16)
            .expect("cache size must be non-zero"),
    )
}

/// Checks whether a batch transaction is authorized, using either event-based authentication
/// or legacy sender verification.
///
/// When batch auth is enabled (`auth_config` is `Some`), there are two authorization paths:
/// 1. **TEE batcher**: must have a matching `BatchInfoAuthenticated` event (checked via
///    `authenticated_hashes`)
/// 2. **Fallback batcher**: authorized via sender verification against `fallback_batcher_address`
///
/// When batch auth is not configured (`auth_config` is `None`), standard OP Stack sender
/// verification is used against `batcher_address`.
pub(crate) fn is_batch_authorized(
    tx: &TxEnvelope,
    batch_hash: B256,
    auth_config: Option<&BatchAuthConfig>,
    authenticated_hashes: &BTreeSet<B256>,
    batcher_address: Address,
) -> bool {
    match auth_config {
        Some(config) => {
            // Event-based authentication: TEE batcher must have an auth event
            if authenticated_hashes.contains(&batch_hash) {
                return true;
            }
            // Fallback batcher: accept via sender verification
            if let Some(fallback_addr) = config.fallback_batcher_address {
                if !fallback_addr.is_zero() {
                    if let Ok(sender) = tx.recover_signer() {
                        if sender == fallback_addr {
                            return true;
                        }
                    }
                }
            }
            false
        }
        None => {
            // Legacy mode: verify sender matches batcher address
            tx.recover_signer().map(|sender| sender == batcher_address).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use alloy_consensus::{Eip658Value, Receipt, Signed, TxLegacy};
    use alloy_primitives::{Address, Log, LogData, Signature, TxKind, address, b256};

    fn make_auth_receipt(authenticator_addr: Address, commitment: B256) -> Receipt {
        let topic0 = BATCH_INFO_AUTHENTICATED_TOPIC;
        let log = Log {
            address: authenticator_addr,
            data: LogData::new_unchecked(vec![topic0, commitment], Default::default()),
        };
        Receipt { status: Eip658Value::Eip658(true), logs: vec![log], ..Default::default() }
    }

    fn make_failed_auth_receipt(authenticator_addr: Address, commitment: B256) -> Receipt {
        let topic0 = BATCH_INFO_AUTHENTICATED_TOPIC;
        let log = Log {
            address: authenticator_addr,
            data: LogData::new_unchecked(vec![topic0, commitment], Default::default()),
        };
        Receipt { status: Eip658Value::Eip658(false), logs: vec![log], ..Default::default() }
    }

    fn test_legacy_tx(to: Address) -> TxEnvelope {
        let sig = Signature::test_signature();
        TxEnvelope::Legacy(Signed::new_unchecked(
            TxLegacy { to: TxKind::Call(to), ..Default::default() },
            sig,
            Default::default(),
        ))
    }

    #[test]
    fn test_compute_calldata_batch_hash() {
        let data = b"hello world";
        let hash = compute_calldata_batch_hash(data);
        assert_eq!(hash, keccak256(data));
    }

    #[test]
    fn test_compute_blob_batch_hash() {
        let h1 = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let h2 = b256!("0000000000000000000000000000000000000000000000000000000000000002");
        let hash = compute_blob_batch_hash(&[h1, h2]);

        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(h1.as_slice());
        expected_input.extend_from_slice(h2.as_slice());
        assert_eq!(hash, keccak256(&expected_input));
    }

    #[test]
    fn test_collect_auth_events_from_receipts_success() {
        let auth_addr = address!("1234567890123456789012345678901234567890");
        let commitment = b256!("abcdef0000000000000000000000000000000000000000000000000000000000");

        let receipt = make_auth_receipt(auth_addr, commitment);
        let result = collect_auth_events_from_receipts(&[receipt], auth_addr);

        assert!(result.contains(&commitment));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_collect_auth_events_from_receipts_wrong_address() {
        let auth_addr = address!("1234567890123456789012345678901234567890");
        let wrong_addr = address!("0000000000000000000000000000000000000001");
        let commitment = b256!("abcdef0000000000000000000000000000000000000000000000000000000000");

        let receipt = make_auth_receipt(wrong_addr, commitment);
        let result = collect_auth_events_from_receipts(&[receipt], auth_addr);

        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_auth_events_from_receipts_failed_receipt() {
        let auth_addr = address!("1234567890123456789012345678901234567890");
        let commitment = b256!("abcdef0000000000000000000000000000000000000000000000000000000000");

        let receipt = make_failed_auth_receipt(auth_addr, commitment);
        let result = collect_auth_events_from_receipts(&[receipt], auth_addr);

        assert!(result.is_empty());
    }

    #[test]
    fn test_collect_auth_events_multiple_events() {
        let auth_addr = address!("1234567890123456789012345678901234567890");
        let c1 = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let c2 = b256!("0000000000000000000000000000000000000000000000000000000000000002");

        let r1 = make_auth_receipt(auth_addr, c1);
        let r2 = make_auth_receipt(auth_addr, c2);
        let result = collect_auth_events_from_receipts(&[r1, r2], auth_addr);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&c1));
        assert!(result.contains(&c2));
    }

    #[test]
    fn test_is_batch_authorized_tee_path() {
        let auth_addr = address!("1234567890123456789012345678901234567890");
        let config =
            BatchAuthConfig { authenticator_address: auth_addr, fallback_batcher_address: None };
        let batch_hash = b256!("abcdef0000000000000000000000000000000000000000000000000000000000");
        let mut authenticated = BTreeSet::new();
        authenticated.insert(batch_hash);

        let tx = test_legacy_tx(Address::ZERO);
        assert!(is_batch_authorized(&tx, batch_hash, Some(&config), &authenticated, Address::ZERO));
    }

    #[test]
    fn test_is_batch_authorized_not_authenticated() {
        let auth_addr = address!("1234567890123456789012345678901234567890");
        let config =
            BatchAuthConfig { authenticator_address: auth_addr, fallback_batcher_address: None };
        let batch_hash = b256!("abcdef0000000000000000000000000000000000000000000000000000000000");
        let authenticated = BTreeSet::new(); // empty

        let tx = test_legacy_tx(Address::ZERO);
        assert!(!is_batch_authorized(
            &tx,
            batch_hash,
            Some(&config),
            &authenticated,
            Address::ZERO
        ));
    }

    #[test]
    fn test_is_batch_authorized_legacy_mode() {
        let batch_hash = B256::ZERO;
        let authenticated = BTreeSet::new();

        let tx = test_legacy_tx(Address::ZERO);
        let sender = tx.recover_signer().unwrap();
        // In legacy mode, sender must match batcher_address
        assert!(is_batch_authorized(&tx, batch_hash, None, &authenticated, sender));
        // Wrong batcher address
        assert!(!is_batch_authorized(
            &tx,
            batch_hash,
            None,
            &authenticated,
            address!("0000000000000000000000000000000000000001"),
        ));
    }

    #[test]
    fn test_batch_info_authenticated_topic_is_correct() {
        assert_eq!(
            BATCH_INFO_AUTHENTICATED_TOPIC,
            keccak256("BatchInfoAuthenticated(bytes32)")
        );
    }

    #[test]
    fn test_new_batch_auth_cache() {
        let cache = new_batch_auth_cache();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.cap().get(), (BATCH_AUTH_LOOKBACK_WINDOW as usize) + 16);
    }
}
