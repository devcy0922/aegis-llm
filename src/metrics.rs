use std::{
    fmt::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone, Default)]
pub struct GatewayMetrics {
    inner: Arc<InnerMetrics>,
}

#[derive(Default)]
struct InnerMetrics {
    requests_total: AtomicU64,
    blocked_total: AtomicU64,
    upstream_errors_total: AtomicU64,
}

impl GatewayMetrics {
    pub fn record_request(&self) {
        self.inner.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.inner.blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_error(&self) {
        self.inner
            .upstream_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP govail_requests_total Total gateway requests\n# TYPE govail_requests_total counter\n{}",
            metric("govail_requests_total", self.inner.requests_total.load(Ordering::Relaxed))
        );
        let _ = writeln!(
            out,
            "# HELP govail_blocked_total Requests blocked by policy or security checks\n# TYPE govail_blocked_total counter\n{}",
            metric("govail_blocked_total", self.inner.blocked_total.load(Ordering::Relaxed))
        );
        let _ = writeln!(
            out,
            "# HELP govail_upstream_errors_total Upstream proxy errors\n# TYPE govail_upstream_errors_total counter\n{}",
            metric(
                "govail_upstream_errors_total",
                self.inner.upstream_errors_total.load(Ordering::Relaxed)
            )
        );
        out
    }
}

fn metric(name: &str, value: u64) -> String {
    format!("{name} {value}")
}
