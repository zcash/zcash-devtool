//! Direct, bounded Zakura JSON-RPC. This wallet does not use lightwalletd.

use anyhow::{Context, Result, ensure};
use reqwest::{Client, Url};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};

use crate::control::Control;

#[derive(Debug)]
pub(crate) struct RpcError {
    pub code: Option<i64>,
    method: String,
    error: Value,
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: Zakura RPC {}", self.method, self.error)
    }
}
impl std::error::Error for RpcError {}

pub struct Rpc {
    client: Client,
    url: Url,
    cookie: Option<PathBuf>,
    runtime: Option<tokio::runtime::Runtime>,
    pub(crate) control: Control,
}

impl Drop for Rpc {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            // An OS DNS lookup can outlive a cancelled request. It owns no wallet
            // state, and must not make runtime teardown block cancellation.
            runtime.shutdown_background();
        }
    }
}

impl Rpc {
    pub fn new(url: &str, cookie: Option<PathBuf>, control: &Control) -> Result<Self> {
        control.check()?;
        let url = Url::parse(url)?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none(),
            "use an HTTP(S) RPC URL without embedded credentials; use --cookie-file for authentication"
        );
        Ok(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            url,
            cookie,
            // The wallet/proof code stays synchronous on its blocking worker,
            // but HTTP waits are futures that can actually be cancelled.
            runtime: Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?,
            ),
            control: control.clone(),
        })
    }

    pub fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let started = std::time::Instant::now();
        let mut bytes_read = 0u64;
        let result = self.call_inner(method, params, &mut bytes_read);
        self.control
            .record_rpc(method, started.elapsed(), bytes_read);
        result
    }

    fn call_inner<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        bytes_read: &mut u64,
    ) -> Result<T> {
        // Never log params: they can include addresses, raw payments or secrets.
        self.control.stage(format!("Requesting {method}…"))?;
        let mut request = self
            .client
            .post(self.url.clone())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}));
        if let Some(path) = &self.cookie {
            let cookie = std::fs::read_to_string(path).context("cannot read RPC cookie")?;
            let (user, password) = cookie
                .trim()
                .split_once(':')
                .context("invalid RPC cookie")?;
            request = request.basic_auth(user, Some(password));
        }
        let (status, bytes) = self.runtime.as_ref().expect("runtime exists until the RPC client drops").block_on(async {
            tokio::select! {
                biased;
                _ = self.control.cancellation.cancelled() => {
                    self.control.check()?;
                    unreachable!("the cancellation token was triggered")
                }
                result = async {
                    let mut response = request.send().await.map_err(reqwest::Error::without_url)
                        .with_context(|| format!("{method}: transport failed (10s connection / 30s request timeout)"))?;
                    let status = response.status();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response.chunk().await.map_err(reqwest::Error::without_url)
                        .with_context(|| format!("{method}: reading response failed"))? {
                        ensure!(chunk.len() <= (16 * 1024 * 1024usize).saturating_sub(bytes.len()),
                            "{method}: RPC response exceeds 16 MiB");
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok::<_, anyhow::Error>((status, bytes))
                } => result,
            }
        })?;
        self.control.check()?;
        *bytes_read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let envelope: Value = serde_json::from_slice(&bytes).context("invalid RPC JSON")?;
        if !envelope["error"].is_null() {
            return Err(RpcError {
                code: envelope["error"]["code"].as_i64(),
                method: method.into(),
                error: envelope["error"].clone(),
            }
            .into());
        }
        ensure!(status.is_success(), "{method}: HTTP {status}");
        ensure!(envelope["id"] == 1, "RPC response ID mismatch");
        Ok(serde_json::from_value(
            envelope
                .get("result")
                .context("missing RPC result")?
                .clone(),
        )?)
    }

    pub fn hash(&self, height: u32) -> Result<String> {
        self.call("getblockhash", json!([height]))
    }
    pub fn height(&self) -> Result<u32> {
        self.call("getblockcount", json!([]))
    }
    pub fn block(&self, height: u32) -> Result<crate::chain::Block> {
        let mut block: crate::chain::Block =
            self.call("gettachyonblock", json!([height.to_string()]))?;
        ensure!(block.height == height, "gettachyonblock height mismatch");
        let ordinary: Value = self.call("getblock", json!([block.hash, 1]))?;
        ensure!(ordinary["hash"] == block.hash, "getblock identity mismatch");
        block.transactions = serde_json::from_value(ordinary["tx"].clone())?;
        for stamp in &block.stamps {
            ensure!(
                block.transactions.get(stamp.transaction_index) == Some(&stamp.txid),
                "stamp transaction position mismatch"
            );
        }
        Ok(block)
    }

    pub fn submit(&self, txid: &str, raw: &str) -> Result<()> {
        let accepted: String = self.call("sendrawtransaction", json!([raw])).context(
            "broadcast outcome may be ambiguous; input remains reserved; retry with submit",
        )?;
        ensure!(
            accepted == txid,
            "node returned a different transaction ID; input remains reserved"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
