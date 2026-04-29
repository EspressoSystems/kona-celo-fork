//! CallData Source

use crate::{
    ChainProvider, DataAvailabilityProvider, PipelineError, PipelineResult,
    sources::batch_auth::{
        BatchAuthCache, BatchAuthConfig, collect_authenticated_batches,
        compute_calldata_batch_hash, is_batch_authorized,
    },
};

use alloc::{boxed::Box, collections::BTreeSet, collections::VecDeque};
use alloy_consensus::{Transaction, TxEnvelope};
use alloy_primitives::{Address, B256, Bytes};
use async_trait::async_trait;
use kona_protocol::BlockInfo;

/// A data iterator that reads from calldata.
#[derive(Debug, Clone)]
pub struct CalldataSource<CP>
where
    CP: ChainProvider + Send,
{
    /// The chain provider to use for the calldata source.
    pub chain_provider: CP,
    /// The batch inbox address.
    pub batch_inbox_address: Address,
    /// Current calldata.
    pub calldata: VecDeque<Bytes>,
    /// Whether the calldata source is open.
    pub open: bool,
    /// Batch authentication configuration. When `Some` and Espresso enforcement is active for
    /// the L2 block timestamp the pipeline is deriving towards, event-based batch authentication
    /// is used. Otherwise (pre-fork or no auth contract configured) the source falls back to
    /// vanilla OP Stack sender verification.
    pub batch_auth_config: Option<BatchAuthConfig>,
    /// L2 timestamp at which Espresso event-only batch authorization enforcement activates.
    /// Sourced from [`kona_genesis::HardForkConfig::espresso_enforcement_time`].
    pub espresso_enforcement_time: Option<u64>,
    /// LRU caches for batch auth lookback window traversal (receipts + headers).
    pub(crate) auth_cache: BatchAuthCache,
}

impl<CP: ChainProvider + Send> CalldataSource<CP> {
    /// Creates a new calldata source.
    pub fn new(
        chain_provider: CP,
        batch_inbox_address: Address,
        batch_auth_config: Option<BatchAuthConfig>,
        espresso_enforcement_time: Option<u64>,
    ) -> Self {
        Self {
            chain_provider,
            batch_inbox_address,
            calldata: VecDeque::new(),
            open: false,
            batch_auth_config,
            espresso_enforcement_time,
            auth_cache: BatchAuthCache::new(),
        }
    }

    /// Returns true when Espresso event-only batch authorization enforcement is active at the
    /// given L2 block timestamp.
    fn is_enforcement_active(&self, l2_block_time: u64) -> bool {
        self.espresso_enforcement_time.is_some_and(|t| l2_block_time >= t)
    }

    /// Loads the calldata into the source if it is not open.
    async fn load_calldata(
        &mut self,
        block_ref: &BlockInfo,
        batcher_address: Address,
        l2_block_time: u64,
    ) -> Result<(), CP::Error> {
        if self.open {
            return Ok(());
        }

        let (_, txs) =
            self.chain_provider.block_info_and_transactions_by_hash(block_ref.hash).await?;

        let enforcement_active = self.is_enforcement_active(l2_block_time);

        // Pre-fork the lookback walk is bypassed entirely so derivation is byte-identical to
        // upstream OP Stack (the BatchAuthenticator events are still emitted on L1 but ignored).
        let authenticated_hashes: BTreeSet<B256> = if enforcement_active {
            if let Some(ref config) = self.batch_auth_config {
                collect_authenticated_batches(
                    &mut self.chain_provider,
                    block_ref,
                    config.authenticator_address,
                    &mut self.auth_cache,
                )
                .await?
            } else {
                BTreeSet::new()
            }
        } else {
            BTreeSet::new()
        };

        self.calldata = txs
            .iter()
            .filter_map(|tx| {
                let (tx_kind, data) = match tx {
                    TxEnvelope::Legacy(tx) => (tx.tx().to(), tx.tx().input()),
                    TxEnvelope::Eip2930(tx) => (tx.tx().to(), tx.tx().input()),
                    TxEnvelope::Eip1559(tx) => (tx.tx().to(), tx.tx().input()),
                    _ => return None,
                };

                let to = tx_kind?;

                if to != self.batch_inbox_address {
                    return None;
                }

                // Compute the batch hash for event-based authentication
                let batch_hash = compute_calldata_batch_hash(data);

                // Check authorization using either event-based or sender-based auth
                if !is_batch_authorized(
                    tx,
                    batch_hash,
                    self.batch_auth_config.as_ref(),
                    &authenticated_hashes,
                    batcher_address,
                    enforcement_active,
                ) {
                    return None;
                }

                Some(data.to_vec().into())
            })
            .collect::<VecDeque<_>>();

        #[cfg(feature = "metrics")]
        metrics::gauge!(
            crate::metrics::Metrics::PIPELINE_DATA_AVAILABILITY_PROVIDER,
            "source" => "calldata",
        )
        .increment(self.calldata.len() as f64);

        self.open = true;

        Ok(())
    }
}

#[async_trait]
impl<CP: ChainProvider + Send> DataAvailabilityProvider for CalldataSource<CP> {
    type Item = Bytes;

    async fn next(
        &mut self,
        block_ref: &BlockInfo,
        batcher_address: Address,
        l2_block_time: u64,
    ) -> PipelineResult<Self::Item> {
        self.load_calldata(block_ref, batcher_address, l2_block_time).await.map_err(Into::into)?;
        self.calldata.pop_front().ok_or(PipelineError::Eof.temp())
    }

    fn clear(&mut self) {
        self.calldata.clear();
        self.open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::batch_auth::BATCH_INFO_AUTHENTICATED_TOPIC;
    use crate::{errors::PipelineErrorKind, test_utils::TestChainProvider};
    use alloc::{vec, vec::Vec};
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_consensus::{
        Eip658Value, Receipt, Signed, TxEip2930, TxEip4844, TxEip4844Variant, TxEip7702, TxLegacy,
    };
    use alloy_primitives::{Address, Log, LogData, Signature, TxKind, address};

    pub(crate) fn test_legacy_tx(to: Address) -> TxEnvelope {
        let sig = Signature::test_signature();
        TxEnvelope::Legacy(Signed::new_unchecked(
            TxLegacy { to: TxKind::Call(to), ..Default::default() },
            sig,
            Default::default(),
        ))
    }

    pub(crate) fn test_eip2930_tx(to: Address) -> TxEnvelope {
        let sig = Signature::test_signature();
        TxEnvelope::Eip2930(Signed::new_unchecked(
            TxEip2930 { to: TxKind::Call(to), ..Default::default() },
            sig,
            Default::default(),
        ))
    }

    pub(crate) fn test_eip7702_tx(to: Address) -> TxEnvelope {
        let sig = Signature::test_signature();
        TxEnvelope::Eip7702(Signed::new_unchecked(
            TxEip7702 { to, ..Default::default() },
            sig,
            Default::default(),
        ))
    }

    pub(crate) fn test_blob_tx(to: Address) -> TxEnvelope {
        let sig = Signature::test_signature();
        TxEnvelope::Eip4844(Signed::new_unchecked(
            TxEip4844Variant::TxEip4844(TxEip4844 { to, ..Default::default() }),
            sig,
            Default::default(),
        ))
    }

    pub(crate) fn default_test_calldata_source() -> CalldataSource<TestChainProvider> {
        CalldataSource::new(TestChainProvider::default(), Default::default(), None, None)
    }

    /// Creates a receipt with a `BatchInfoAuthenticated` event for the given commitment.
    fn make_auth_receipt(authenticator_addr: Address, commitment: B256) -> Receipt {
        let topic0 = BATCH_INFO_AUTHENTICATED_TOPIC;
        let signer_topic = B256::ZERO;
        let log = Log {
            address: authenticator_addr,
            data: LogData::new_unchecked(
                vec![topic0, commitment, signer_topic],
                Default::default(),
            ),
        };
        Receipt { status: Eip658Value::Eip658(true), logs: vec![log], ..Default::default() }
    }

    #[tokio::test]
    async fn test_clear_calldata() {
        let mut source = default_test_calldata_source();
        source.open = true;
        source.calldata.push_back(Bytes::default());
        source.clear();
        assert!(source.calldata.is_empty());
        assert!(!source.open);
    }

    /// Pre-fork: an L2 block time of 0 with no enforcement timestamp set means we run vanilla
    /// OP Stack semantics (sender-based authorization, BatchAuthenticator events ignored).
    const PRE_FORK_L2_TIME: u64 = 0;

    /// Post-fork: with `espresso_enforcement_time = Some(100)`, an L2 block time >= 100 is
    /// post-fork (event-only authorization, sender fallback rejected).
    const ENFORCEMENT_TIME: u64 = 100;
    const POST_FORK_L2_TIME: u64 = 100;

    #[tokio::test]
    async fn test_load_calldata_open() {
        let mut source = default_test_calldata_source();
        source.open = true;
        assert!(
            source
                .load_calldata(&BlockInfo::default(), Address::ZERO, PRE_FORK_L2_TIME)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_load_calldata_provider_err() {
        let mut source = default_test_calldata_source();
        assert!(
            source
                .load_calldata(&BlockInfo::default(), Address::ZERO, PRE_FORK_L2_TIME)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_load_calldata_chain_provider_empty_txs() {
        let mut source = default_test_calldata_source();
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, Vec::new());
        assert!(!source.open); // Source is not open by default.
        assert!(
            source
                .load_calldata(&BlockInfo::default(), Address::ZERO, PRE_FORK_L2_TIME)
                .await
                .is_ok()
        );
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }

    #[tokio::test]
    async fn test_load_calldata_wrong_batch_inbox_address() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        let block_info = BlockInfo::default();
        let tx = test_legacy_tx(batch_inbox_address);
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        assert!(!source.open); // Source is not open by default.
        assert!(
            source
                .load_calldata(&BlockInfo::default(), Address::ZERO, PRE_FORK_L2_TIME)
                .await
                .is_ok()
        );
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }

    // Pre-fork (vanilla OP), sender must match batcher_address.
    #[tokio::test]
    async fn test_load_calldata_valid_legacy_tx_sender_check() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_legacy_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        assert!(!source.open);
        // Use the correct signer address as batcher_address
        assert!(
            source
                .load_calldata(
                    &BlockInfo::default(),
                    tx.recover_signer().unwrap(),
                    PRE_FORK_L2_TIME,
                )
                .await
                .is_ok()
        );
        assert!(!source.calldata.is_empty()); // Calldata is NOT empty.
        assert!(source.open);
    }

    // Pre-fork (vanilla OP), wrong batcher_address should reject.
    #[tokio::test]
    async fn test_load_calldata_wrong_batcher_address_rejected() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_legacy_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        assert!(!source.open);
        // Use wrong batcher address
        let wrong_batcher = address!("0000000000000000000000000000000000000001");
        assert!(
            source
                .load_calldata(&BlockInfo::default(), wrong_batcher, PRE_FORK_L2_TIME)
                .await
                .is_ok()
        );
        assert!(source.calldata.is_empty()); // Rejected: wrong sender
        assert!(source.open);
    }

    #[tokio::test]
    async fn test_load_calldata_valid_eip2930_tx() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_eip2930_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        assert!(!source.open);
        assert!(
            source
                .load_calldata(
                    &BlockInfo::default(),
                    tx.recover_signer().unwrap(),
                    PRE_FORK_L2_TIME,
                )
                .await
                .is_ok()
        );
        assert!(!source.calldata.is_empty()); // Calldata is NOT empty.
        assert!(source.open);
    }

    #[tokio::test]
    async fn test_load_calldata_blob_tx_ignored() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_blob_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        assert!(!source.open);
        assert!(
            source
                .load_calldata(
                    &BlockInfo::default(),
                    tx.recover_signer().unwrap(),
                    PRE_FORK_L2_TIME,
                )
                .await
                .is_ok()
        );
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }

    #[tokio::test]
    async fn test_load_calldata_eip7702_tx_ignored() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_eip7702_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        assert!(!source.open);
        assert!(
            source
                .load_calldata(
                    &BlockInfo::default(),
                    tx.recover_signer().unwrap(),
                    PRE_FORK_L2_TIME,
                )
                .await
                .is_ok()
        );
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }

    #[tokio::test]
    async fn test_next_err_loading_calldata() {
        let mut source = default_test_calldata_source();
        assert!(matches!(
            source.next(&BlockInfo::default(), Address::ZERO, PRE_FORK_L2_TIME).await,
            Err(PipelineErrorKind::Temporary(_))
        ));
    }

    // Post-fork: event-based batch authentication, Espresso batcher path.
    #[tokio::test]
    async fn test_load_calldata_post_fork_event_authenticated() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let authenticator_addr = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let config = BatchAuthConfig { authenticator_address: authenticator_addr };
        let mut source = CalldataSource::new(
            TestChainProvider::default(),
            batch_inbox_address,
            Some(config),
            Some(ENFORCEMENT_TIME),
        );

        let tx = test_legacy_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);

        // Compute the expected batch hash for the tx data (empty calldata)
        let batch_hash = compute_calldata_batch_hash(b"");

        // Insert a receipt with a matching BatchInfoAuthenticated event
        let auth_receipt = make_auth_receipt(authenticator_addr, batch_hash);
        source.chain_provider.insert_receipts(block_info.hash, vec![auth_receipt]);

        // Insert a header for the block so the lookback traversal can resolve it
        let header = alloy_consensus::Header { number: 0, ..Default::default() };
        source.chain_provider.insert_header(block_info.hash, header);

        assert!(source.load_calldata(&block_info, Address::ZERO, POST_FORK_L2_TIME).await.is_ok());
        assert!(!source.calldata.is_empty()); // Authenticated via event
        assert!(source.open);
    }

    // Post-fork: unknown sender, no auth event => rejected.
    #[tokio::test]
    async fn test_load_calldata_post_fork_not_authenticated() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let authenticator_addr = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let config = BatchAuthConfig { authenticator_address: authenticator_addr };
        let mut source = CalldataSource::new(
            TestChainProvider::default(),
            batch_inbox_address,
            Some(config),
            Some(ENFORCEMENT_TIME),
        );

        let tx = test_legacy_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);

        // Insert empty receipts (no auth event)
        let empty_receipt = Receipt { status: Eip658Value::Eip658(true), ..Default::default() };
        source.chain_provider.insert_receipts(block_info.hash, vec![empty_receipt]);

        let header = alloy_consensus::Header { number: 0, ..Default::default() };
        source.chain_provider.insert_header(block_info.hash, header);

        assert!(source.load_calldata(&block_info, Address::ZERO, POST_FORK_L2_TIME).await.is_ok());
        assert!(source.calldata.is_empty()); // Not authenticated
        assert!(source.open);
    }

    // Post-fork: sender-based fallback is rejected even when sender matches batcher_address.
    // Mirrors the Go PR #409 verifier semantics: post-fork = event-only.
    #[tokio::test]
    async fn test_load_calldata_post_fork_sender_fallback_rejected() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let authenticator_addr = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let tx = test_legacy_tx(batch_inbox_address);
        let batcher_address = tx.recover_signer().unwrap();

        let config = BatchAuthConfig { authenticator_address: authenticator_addr };
        let mut source = CalldataSource::new(
            TestChainProvider::default(),
            batch_inbox_address,
            Some(config),
            Some(ENFORCEMENT_TIME),
        );

        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);

        // Insert empty receipts (no auth event)
        let empty_receipt = Receipt { status: Eip658Value::Eip658(true), ..Default::default() };
        source.chain_provider.insert_receipts(block_info.hash, vec![empty_receipt]);

        let header = alloy_consensus::Header { number: 0, ..Default::default() };
        source.chain_provider.insert_header(block_info.hash, header);

        // Even though `batcher_address` matches the tx sender, post-fork the sender check is
        // gated off and only events authorize.
        assert!(
            source.load_calldata(&block_info, batcher_address, POST_FORK_L2_TIME).await.is_ok()
        );
        assert!(source.calldata.is_empty()); // Sender fallback rejected post-fork
        assert!(source.open);
    }

    // Pre-fork: authorization via sender match works even when a `BatchAuthenticator` is
    // configured. The auth event lookback is bypassed entirely so derivation matches upstream
    // OP Stack byte-for-byte.
    #[tokio::test]
    async fn test_load_calldata_pre_fork_ignores_auth_event() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let authenticator_addr = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let tx = test_legacy_tx(batch_inbox_address);
        let batcher_address = tx.recover_signer().unwrap();

        let config = BatchAuthConfig { authenticator_address: authenticator_addr };
        // Enforcement is set but L2 time is pre-fork.
        let mut source = CalldataSource::new(
            TestChainProvider::default(),
            batch_inbox_address,
            Some(config),
            Some(ENFORCEMENT_TIME),
        );

        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);

        // We do NOT insert any receipts/header — this should be unreachable when pre-fork
        // because the lookback walk is skipped. If the gate regresses, this test will fail with
        // a provider error instead of silently passing.

        assert!(source.load_calldata(&block_info, batcher_address, PRE_FORK_L2_TIME).await.is_ok());
        assert!(!source.calldata.is_empty()); // Authorized via sender path (vanilla OP)
        assert!(source.open);
    }
}
