//! OMQ client for `bridge.committee` (Phase B.9 transport).
//!
//! The signer reads its committee view from its own `beldexd` over OxenMQ. There
//! is no mature pure-Rust OxenMQ binding, but a *request/reply* over the local
//! plain IPC socket is just the underlying ZMQ protocol OMQ speaks:
//!
//!   request  (DEALER send): [ "bridge.committee", <tag>, <optional height> ]
//!   reply    (DEALER recv): [ "REPLY", <tag>, "<status>", <data...> ]
//!
//! where `<status>` is `"200"` on success and `<data[0]>` is the JSON committee
//! reply (parsed by [`crate::committee::CommitteeView::from_bridge_committee_json`]).
//! The local socket authenticates connections at admin level ("unauthenticated
//! local admin"), so no curve keypair is needed for the operator's own node.
//!
//! This is the minimal committee-read transport; the full session engine (C.4)
//! is a larger OMQ surface and is separate work. Built under `--features omq-client`.

use crate::committee::{CommitteeError, CommitteeView};
use std::time::Duration;

/// A thin client that fetches the committee view from a `beldexd` OMQ endpoint.
pub struct OmqCommitteeClient {
    ctx: zmq::Context,
    endpoint: String,
    timeout: Duration,
}

impl OmqCommitteeClient {
    /// Create a client for `endpoint` (e.g. `ipc:///…/beldexd.sock` or
    /// `tcp://127.0.0.1:PORT`). A fresh DEALER socket is opened per request so a
    /// timed-out request can never desync a long-lived socket's reply framing.
    pub fn new(endpoint: impl Into<String>) -> Self {
        OmqCommitteeClient {
            ctx: zmq::Context::new(),
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(5),
        }
    }

    /// Override the request timeout (default 5s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Call `bridge.committee` and return the parsed committee for `height`
    /// (the epoch containing it; `None` = current tip).
    pub fn fetch_committee(&self, height: Option<u64>) -> Result<CommitteeView, CommitteeError> {
        let tx = |e: String| CommitteeError::Transport(e);

        let sock = self
            .ctx
            .socket(zmq::DEALER)
            .map_err(|e| tx(format!("socket: {e}")))?;
        // Don't linger on close; a dead endpoint must not block teardown.
        sock.set_linger(0).map_err(|e| tx(format!("set_linger: {e}")))?;
        sock.connect(&self.endpoint)
            .map_err(|e| tx(format!("connect {}: {e}", self.endpoint)))?;

        // request parts: command, correlation tag, [optional height as ASCII]
        let height_str;
        let mut parts: Vec<&[u8]> = vec![b"bridge.committee", b"bridgesig-committee"];
        if let Some(h) = height {
            height_str = h.to_string();
            parts.push(height_str.as_bytes());
        }
        sock.send_multipart(parts, 0)
            .map_err(|e| tx(format!("send: {e}")))?;

        // Wait for the reply with a bounded timeout so a hung daemon can't stall
        // the signer.
        let ms = self.timeout.as_millis() as i64;
        let mut items = [sock.as_poll_item(zmq::POLLIN)];
        let ready = zmq::poll(&mut items, ms).map_err(|e| tx(format!("poll: {e}")))?;
        if ready == 0 {
            return Err(tx(format!("timeout after {ms}ms waiting for {}", self.endpoint)));
        }

        let reply = sock
            .recv_multipart(0)
            .map_err(|e| tx(format!("recv: {e}")))?;

        // [ REPLY, tag, status, data... ]
        if reply.len() < 3 || reply[0] != b"REPLY" {
            return Err(tx(format!("unexpected {}-part reply", reply.len())));
        }
        let status = String::from_utf8_lossy(&reply[2]);
        if status != "200" {
            let body = reply.get(3).map(|d| String::from_utf8_lossy(d).into_owned());
            return Err(tx(format!(
                "daemon returned status {status}{}",
                body.map(|b| format!(": {b}")).unwrap_or_default()
            )));
        }

        let data = reply.get(3).ok_or_else(|| tx("empty reply data".into()))?;
        let json = std::str::from_utf8(data).map_err(|_| tx("reply not utf-8".into()))?;
        CommitteeView::from_bridge_committee_json(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration test against a live beldexd. Ignored by default (needs a running
    // node); run explicitly against the devnet:
    //
    //   BRIDGE_SIGNER_OXENMQ_ENDPOINT=ipc://$PWD/utils/local-devnet/testdata/\
    //     beldex-127.0.0.1-<PORT>/devnet/beldexd.sock \
    //   cargo test -p beldex-bridge-signer --features omq-client -- --ignored fetches_live_committee
    #[test]
    #[ignore = "requires a running beldexd with an active bridge committee"]
    fn fetches_live_committee() {
        let endpoint = std::env::var("BRIDGE_SIGNER_OXENMQ_ENDPOINT")
            .expect("set BRIDGE_SIGNER_OXENMQ_ENDPOINT to a beldexd OMQ socket");
        let client = OmqCommitteeClient::new(endpoint);
        let view = client.fetch_committee(None).expect("fetch committee");
        assert!(view.can_sign(), "committee should be signable: {view:?}");
        assert_eq!(view.size(), view.members.len());
        eprintln!(
            "live committee: epoch={} height={} size={} threshold={}",
            view.epoch,
            view.height,
            view.size(),
            view.threshold
        );
    }
}
