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
    /// Batch authentication configuration. When `Some`, event-based batch authentication
    /// is used. When `None`, legacy sender-based authentication is used.
    pub batch_auth_config: Option<BatchAuthConfig>,
    /// LRU caches for batch auth lookback window traversal (receipts + headers).
    pub(crate) auth_cache: BatchAuthCache,
}

impl<CP: ChainProvider + Send> CalldataSource<CP> {
    /// Creates a new calldata source.
    pub fn new(
        chain_provider: CP,
        batch_inbox_address: Address,
        batch_auth_config: Option<BatchAuthConfig>,
    ) -> Self {
        Self {
            chain_provider,
            batch_inbox_address,
            calldata: VecDeque::new(),
            open: false,
            batch_auth_config,
            auth_cache: BatchAuthCache::new(),
        }
    }

    /// Loads the calldata into the source if it is not open.
    async fn load_calldata(
        &mut self,
        block_ref: &BlockInfo,
        batcher_address: Address,
    ) -> Result<(), CP::Error> {
        if self.open {
            return Ok(());
        }

        let (_, txs) =
            self.chain_provider.block_info_and_transactions_by_hash(block_ref.hash).await?;

        // Collect authenticated batch hashes from the lookback window when batch auth is enabled.
        // We do this once per block and pass the set to the filter below.
        let authenticated_hashes: BTreeSet<B256> = if let Some(ref config) = self.batch_auth_config
        {
            collect_authenticated_batches(
                &mut self.chain_provider,
                block_ref,
                config.authenticator_address,
                &mut self.auth_cache,
            )
            .await?
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
    ) -> PipelineResult<Self::Item> {
        self.load_calldata(block_ref, batcher_address).await.map_err(Into::into)?;
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
        CalldataSource::new(TestChainProvider::default(), Default::default(), None)
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

    #[tokio::test]
    async fn test_load_calldata_open() {
        let mut source = default_test_calldata_source();
        source.open = true;
        assert!(source.load_calldata(&BlockInfo::default(), Address::ZERO).await.is_ok());
    }

    #[tokio::test]
    async fn test_load_calldata_provider_err() {
        let mut source = default_test_calldata_source();
        assert!(source.load_calldata(&BlockInfo::default(), Address::ZERO).await.is_err());
    }

    #[tokio::test]
    async fn test_load_calldata_chain_provider_empty_txs() {
        let mut source = default_test_calldata_source();
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, Vec::new());
        assert!(!source.open); // Source is not open by default.
        assert!(source.load_calldata(&BlockInfo::default(), Address::ZERO).await.is_ok());
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
        assert!(source.load_calldata(&BlockInfo::default(), Address::ZERO).await.is_ok());
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }

    // In legacy mode (no batch auth), sender must match batcher_address.
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
            source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok()
        );
        assert!(!source.calldata.is_empty()); // Calldata is NOT empty.
        assert!(source.open);
    }

    // In legacy mode, wrong batcher_address should reject.
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
        assert!(source.load_calldata(&BlockInfo::default(), wrong_batcher).await.is_ok());
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
            source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok()
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
            source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok()
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
            source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok()
        );
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }

    #[tokio::test]
    async fn test_next_err_loading_calldata() {
        let mut source = default_test_calldata_source();
        assert!(matches!(
            source.next(&BlockInfo::default(), Address::ZERO).await,
            Err(PipelineErrorKind::Temporary(_))
        ));
    }

    // Test event-based batch authentication: TEE batcher path.
    #[tokio::test]
    async fn test_load_calldata_batch_auth_tee_path() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let authenticator_addr = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let config = BatchAuthConfig {
            authenticator_address: authenticator_addr,
            fallback_batcher_address: None,
        };
        let mut source =
            CalldataSource::new(TestChainProvider::default(), batch_inbox_address, Some(config));

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

        assert!(source.load_calldata(&block_info, Address::ZERO).await.is_ok());
        assert!(!source.calldata.is_empty()); // Authenticated via event
        assert!(source.open);
    }

    // Test event-based batch authentication: batch not authenticated, no fallback.
    #[tokio::test]
    async fn test_load_calldata_batch_auth_not_authenticated() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let authenticator_addr = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let config = BatchAuthConfig {
            authenticator_address: authenticator_addr,
            fallback_batcher_address: None,
        };
        let mut source =
            CalldataSource::new(TestChainProvider::default(), batch_inbox_address, Some(config));

        let tx = test_legacy_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);

        // Insert empty receipts (no auth event)
        let empty_receipt = Receipt { status: Eip658Value::Eip658(true), ..Default::default() };
        source.chain_provider.insert_receipts(block_info.hash, vec![empty_receipt]);

        let header = alloy_consensus::Header { number: 0, ..Default::default() };
        source.chain_provider.insert_header(block_info.hash, header);

        assert!(source.load_calldata(&block_info, Address::ZERO).await.is_ok());
        assert!(source.calldata.is_empty()); // Not authenticated
        assert!(source.open);
    }

    // Test event-based batch authentication: fallback batcher path.
    #[tokio::test]
    async fn test_load_calldata_batch_auth_fallback_batcher() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let authenticator_addr = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let tx = test_legacy_tx(batch_inbox_address);
        let fallback_batcher = tx.recover_signer().unwrap();

        let config = BatchAuthConfig {
            authenticator_address: authenticator_addr,
            fallback_batcher_address: Some(fallback_batcher),
        };
        let mut source =
            CalldataSource::new(TestChainProvider::default(), batch_inbox_address, Some(config));

        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);

        // Insert empty receipts (no auth event)
        let empty_receipt = Receipt { status: Eip658Value::Eip658(true), ..Default::default() };
        source.chain_provider.insert_receipts(block_info.hash, vec![empty_receipt]);

        let header = alloy_consensus::Header { number: 0, ..Default::default() };
        source.chain_provider.insert_header(block_info.hash, header);

        assert!(source.load_calldata(&block_info, Address::ZERO).await.is_ok());
        assert!(!source.calldata.is_empty()); // Authorized via fallback sender
        assert!(source.open);
    }
}
