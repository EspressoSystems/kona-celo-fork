//! CallData Source

use crate::{ChainProvider, DataAvailabilityProvider, PipelineError, PipelineResult};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use alloy_consensus::{Receipt, Transaction, TxEnvelope, TxReceipt};
use alloy_primitives::{Address, Bytes};
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
}

impl<CP: ChainProvider + Send> CalldataSource<CP> {
    /// Creates a new calldata source.
    pub const fn new(chain_provider: CP, batch_inbox_address: Address) -> Self {
        Self { chain_provider, batch_inbox_address, calldata: VecDeque::new(), open: false }
    }

    /// Loads the calldata into the source if it is not open.
    async fn load_calldata(
        &mut self,
        block_ref: &BlockInfo,
        _batcher_address: Address,
    ) -> Result<(), CP::Error> {
        if self.open {
            return Ok(());
        }

        let (_, txs) =
            self.chain_provider.block_info_and_transactions_by_hash(block_ref.hash).await?;

        let mut receipts: Vec<Receipt> = Vec::new();
        // only fetch receipts if there are transactions
        if !txs.is_empty() {
            receipts = self.chain_provider.receipts_by_hash(block_ref.hash).await?;
        }

        self.calldata = txs
            .iter()
            .enumerate()
            .filter_map(|(index, tx)| {
                let (tx_kind, data) = match tx {
                    TxEnvelope::Legacy(tx) => (tx.tx().to(), tx.tx().input()),
                    TxEnvelope::Eip2930(tx) => (tx.tx().to(), tx.tx().input()),
                    TxEnvelope::Eip1559(tx) => (tx.tx().to(), tx.tx().input()),
                    _ => return None,
                };

                // Get the corresponding receipt, if the receipt status is false,
                // that means it cant be valid batch inbox tx.
                // TODO: In future, we should add a conditional check that this should only be done
                // for txs after Espresso migration.
                let receipt: &Receipt = receipts.get(index)?;
                if !receipt.status() {
                    return None;
                }
                let to = tx_kind?;

                if to != self.batch_inbox_address {
                    return None;
                }

                // NOTE: contrary to a standard OP batcher, we can safely skip any verification related
                // to the sender of the transaction. Indeed, the Batch Inbox contract takes care of
                // ensuring the sender of the batch information is a legitimate batcher.
                // Thus, the parameter `batcher_address` is not used anymore.
                // However, it is kept for compatibility with upstream code.

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
    use crate::{errors::PipelineErrorKind, test_utils::TestChainProvider};
    use alloc::{vec, vec::Vec};
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_consensus::{
        Eip658Value, Signed, TxEip2930, TxEip4844, TxEip4844Variant, TxEip7702, TxLegacy,
    };
    use alloy_primitives::{Address, Signature, TxKind, address};

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
        CalldataSource::new(TestChainProvider::default(), Default::default())
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
        let receipt = Receipt {
            cumulative_gas_used: 42000,
            status: Eip658Value::Eip658(true),
            ..Default::default()
        };
        source.chain_provider.insert_receipts(block_info.hash, vec![receipt]);
        assert!(!source.open); // Source is not open by default.
        assert!(source.load_calldata(&BlockInfo::default(), Address::ZERO).await.is_ok());
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }

    #[tokio::test]
    async fn test_load_calldata_valid_legacy_tx() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_legacy_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        let receipt = Receipt {
            cumulative_gas_used: 42000,
            status: Eip658Value::Eip658(true),
            ..Default::default()
        };
        source.chain_provider.insert_receipts(block_info.hash, vec![receipt]);
        assert!(!source.open); // Source is not open by default.
        assert!(
            source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok()
        );
        assert!(!source.calldata.is_empty()); // Calldata is NOT empty.
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
        let receipt = Receipt {
            cumulative_gas_used: 42000,
            status: Eip658Value::Eip658(true),
            ..Default::default()
        };
        source.chain_provider.insert_receipts(block_info.hash, vec![receipt]);
        assert!(!source.open); // Source is not open by default.
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
        let receipt = Receipt {
            cumulative_gas_used: 42000,
            status: Eip658Value::Eip658(true),
            ..Default::default()
        };
        source.chain_provider.insert_receipts(block_info.hash, vec![receipt]);
        assert!(!source.open); // Source is not open by default.
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
        let receipt = Receipt {
            cumulative_gas_used: 42000,
            status: Eip658Value::Eip658(true),
            ..Default::default()
        };
        source.chain_provider.insert_receipts(block_info.hash, vec![receipt]);
        assert!(!source.open); // Source is not open by default.
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

    // Test if the receipt status true causes the calldata to be processed.
    #[tokio::test]
    async fn test_non_empty_calldata_if_receipt_status_true() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_eip2930_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        // Insert a receipt with status true.
        let receipt = Receipt {
            cumulative_gas_used: 42000,
            status: Eip658Value::Eip658(true),
            ..Default::default()
        };
        source.chain_provider.insert_receipts(block_info.hash, vec![receipt]);
        assert!(!source.open); // Source is not open by default.
        assert!(
            source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok()
        );
        assert!(!source.calldata.is_empty());
        assert!(source.open);
    }

    // Test if the receipt status false causes the calldata to be ignored.
    #[tokio::test]
    async fn test_empty_calldata_if_receipt_status_false() {
        let batch_inbox_address = address!("0123456789012345678901234567890123456789");
        let mut source = default_test_calldata_source();
        source.batch_inbox_address = batch_inbox_address;
        let tx = test_eip2930_tx(batch_inbox_address);
        let block_info = BlockInfo::default();
        source.chain_provider.insert_block_with_transactions(0, block_info, vec![tx.clone()]);
        // Insert a receipt with status false.
        let receipt = Receipt {
            cumulative_gas_used: 42000,
            status: Eip658Value::Eip658(false),
            ..Default::default()
        };
        source.chain_provider.insert_receipts(block_info.hash, vec![receipt]);
        assert!(!source.open); // Source is not open by default.
        assert!(
            source.load_calldata(&BlockInfo::default(), tx.recover_signer().unwrap()).await.is_ok()
        );
        assert!(source.calldata.is_empty());
        assert!(source.open);
    }
}
