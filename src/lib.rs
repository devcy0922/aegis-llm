pub mod audit;
pub mod auth;
pub mod config;
pub mod langfuse;
pub mod memory;
pub mod metrics;
pub mod model_policy;
pub mod proxy;
pub mod responses_adapter;
pub mod router;
pub mod security;

use std::{collections::HashMap, sync::Arc, time::Instant};

use audit::AuditLogger;
use auth::Principal;
use config::GatewayConfig;
use langfuse::LangfuseClient;
use memory::MemoryClient;
use metrics::GatewayMetrics;
use proxy::ProxyClient;
use router::RouterClient;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<GatewayConfig>,
    pub proxy: ProxyClient,
    pub router: RouterClient,
    pub audit: AuditLogger,
    pub langfuse: LangfuseClient,
    pub memory: MemoryClient,
    pub metrics: GatewayMetrics,
    pub limiter: auth::RateLimiter,
    pub db_client: reqwest::Client,
    pub project_secrets: Arc<tokio::sync::RwLock<HashMap<String, (String, Instant)>>>,
    pub api_key_cache: Arc<tokio::sync::RwLock<HashMap<String, (Principal, Instant)>>>,
}

impl AppState {
    pub fn new(config: GatewayConfig) -> anyhow::Result<Self> {
        let config = Arc::new(config);
        Ok(Self {
            proxy: ProxyClient::new(config.clone())?,
            router: RouterClient::new(config.clone())?,
            audit: AuditLogger::new(config.security.audit_log_path.clone()),
            langfuse: LangfuseClient::new(config.clone()),
            memory: MemoryClient::new(config.clone())?,
            metrics: GatewayMetrics::default(),
            limiter: auth::RateLimiter::default(),
            db_client: reqwest::Client::new(),
            project_secrets: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            api_key_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            config,
        })
    }
}
