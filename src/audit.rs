use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::memory::MemoryAudit;

#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<AuditEvent>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuditEvent {
    pub ts: DateTime<Utc>,
    pub trace_id: String,
    pub key_id: String,
    pub key_hash: String,
    pub project: String,
    pub model: Option<String>,
    pub route: String,
    pub status: String,
    pub finding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryAudit>,
    pub latency_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(1024);

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(err) = write_event_to_file(&path, &event).await {
                    eprintln!("failed to write audit event: {:?}", err);
                }
            }
        });

        Self { tx }
    }

    pub async fn append(&self, event: &AuditEvent) -> anyhow::Result<()> {
        self.tx
            .send(event.clone())
            .await
            .map_err(|_| anyhow::anyhow!("audit channel closed"))?;
        Ok(())
    }
}

async fn write_event_to_file(path: &std::path::Path, event: &AuditEvent) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).append(true);
    let mut file = options.open(path).await?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&line).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn enforces_concurrency_and_no_loss() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let logger = AuditLogger::new(path.clone());
        let mut handles = vec![];

        let num_tasks = 20;
        let events_per_task = 50;

        for t in 0..num_tasks {
            let logger = logger.clone();
            handles.push(tokio::spawn(async move {
                for e in 0..events_per_task {
                    let event = AuditEvent {
                        ts: Utc::now(),
                        trace_id: format!("trace-{}-{}", t, e),
                        key_id: "test_key".to_string(),
                        key_hash: "hash".to_string(),
                        project: "test_project".to_string(),
                        model: Some("test_model".to_string()),
                        route: "test_route".to_string(),
                        status: "test_status".to_string(),
                        finding: None,
                        memory: None,
                        latency_ms: 42,
                        request: None,
                        response: None,
                    };
                    logger.append(&event).await.unwrap();
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // 백그라운드 스레드에서 파일 쓰기가 끝날 시간을 확보
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = content
            .trim()
            .split('\n')
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(lines.len(), num_tasks * events_per_task);

        for line in lines {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(event["key_id"], "test_key");
        }
    }
}
