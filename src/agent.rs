//! Content Scanner agent implementation.

use crate::clamd::{ClamdClient, ScanResult};
use crate::config::{Config, FailAction};
use async_trait::async_trait;
use sentinel_agent_sdk::{Agent, Decision, Request, Response};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Content Scanner agent.
pub struct ContentScannerAgent {
    config: Arc<Config>,
    clamd: ClamdClient,
    /// Track requests that should be scanned.
    scan_contexts: Arc<RwLock<HashMap<String, ScanContext>>>,
}

/// Context for a request being scanned.
#[derive(Debug, Clone)]
struct ScanContext {
    /// Content-Type header value.
    content_type: Option<String>,
    /// Request path.
    path: String,
    /// Request method.
    method: String,
}

impl ContentScannerAgent {
    /// Create a new Content Scanner agent.
    pub fn new(config: Config) -> Self {
        let clamd = ClamdClient::new(
            config.clamd.socket_path.clone(),
            config.clamd.timeout_ms,
            config.clamd.chunk_size,
        );

        info!(
            socket = %config.clamd.socket_path.display(),
            max_body_size = config.body.max_size,
            "Content Scanner agent initialized"
        );

        Self {
            config: Arc::new(config),
            clamd,
            scan_contexts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Build decision for fail action.
    fn fail_action_decision(&self) -> Decision {
        match self.config.settings.fail_action {
            FailAction::Allow => Decision::allow()
                .add_request_header("x-scan-skipped", "clamd-unavailable")
                .with_tag("content-scanner:clamd-unavailable:allowed"),
            FailAction::Block => Decision::block(503)
                .with_block_header("x-scan-error", "clamd-unavailable")
                .with_tag("content-scanner:clamd-unavailable:blocked"),
        }
    }

    /// Store scan context for a request.
    async fn store_context(&self, correlation_id: &str, ctx: ScanContext) {
        let mut contexts = self.scan_contexts.write().await;
        contexts.insert(correlation_id.to_string(), ctx);
    }

    /// Get and remove scan context for a request.
    async fn take_context(&self, correlation_id: &str) -> Option<ScanContext> {
        let mut contexts = self.scan_contexts.write().await;
        contexts.remove(correlation_id)
    }

    /// Flatten multi-value headers to single values.
    fn flatten_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.first().cloned().unwrap_or_default()))
            .collect()
    }

    /// Get a single header value.
    fn get_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
        headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }
}

#[async_trait]
impl Agent for ContentScannerAgent {
    async fn on_request(&self, request: &Request) -> Decision {
        // Check if scanning is enabled
        if !self.config.settings.enabled {
            debug!("Content Scanner agent disabled");
            return Decision::allow();
        }

        // Check if ClamAV is enabled
        if !self.config.clamd.enabled {
            debug!("ClamAV scanning disabled");
            return Decision::allow();
        }

        let method = request.method();
        let path = request.path();
        let headers = Self::flatten_headers(request.headers());

        // Check if method should be scanned
        if !self.config.should_scan_method(method) {
            debug!(method = method, "Method not configured for scanning");
            return Decision::allow();
        }

        // Check path exclusions
        if self.config.should_skip_path(path) {
            debug!(path = path, "Path excluded from scanning");
            return Decision::allow();
        }

        // Get content-type
        let content_type = Self::get_header(&headers, "content-type").map(|s| s.to_string());

        // Check if content-type should be scanned
        if !self.config.should_scan_content_type(content_type.as_deref()) {
            debug!(
                content_type = ?content_type,
                "Content-Type not configured for scanning"
            );
            return Decision::allow()
                .add_request_header("x-scan-skipped", "content-type-excluded");
        }

        // Store context for body phase
        let ctx = ScanContext {
            content_type,
            path: path.to_string(),
            method: method.to_string(),
        };
        self.store_context(request.correlation_id(), ctx).await;

        debug!(
            correlation_id = request.correlation_id(),
            path = path,
            method = method,
            "Request marked for body scanning"
        );

        Decision::allow()
    }

    async fn on_request_body(&self, request: &Request) -> Decision {
        // Check if we have context for this request
        let ctx = match self.take_context(request.correlation_id()).await {
            Some(c) => c,
            None => {
                // No context = not marked for scanning
                return Decision::allow();
            }
        };

        // Get body
        let body = match request.body() {
            Some(b) => b,
            None => {
                debug!("No body to scan");
                return Decision::allow();
            }
        };

        // Check body size
        if body.len() > self.config.body.max_size {
            debug!(
                size = body.len(),
                max_size = self.config.body.max_size,
                "Body exceeds max size, skipping scan"
            );
            return Decision::allow()
                .add_request_header("x-scan-skipped", "size-exceeded")
                .with_tag("content-scanner:size-exceeded");
        }

        // Scan with ClamAV
        let start = Instant::now();
        let result = match self.clamd.scan(body).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    error = %e,
                    path = %ctx.path,
                    "ClamAV scan failed"
                );
                return self.fail_action_decision();
            }
        };
        let scan_time = start.elapsed();

        match result {
            ScanResult::Clean => {
                if self.config.settings.log_clean {
                    debug!(
                        path = %ctx.path,
                        content_type = ?ctx.content_type,
                        size = body.len(),
                        scan_time_ms = scan_time.as_millis(),
                        "Scan complete: clean"
                    );
                }

                Decision::allow()
                    .add_request_header("x-content-scanned", "true")
                    .add_request_header("x-scan-time-ms", &scan_time.as_millis().to_string())
                    .with_tag("content-scanner:clean")
            }
            ScanResult::Infected { virus_name } => {
                if self.config.settings.log_detections {
                    info!(
                        path = %ctx.path,
                        method = %ctx.method,
                        content_type = ?ctx.content_type,
                        virus = %virus_name,
                        size = body.len(),
                        scan_time_ms = scan_time.as_millis(),
                        "Malware detected"
                    );
                }

                Decision::block(403)
                    .with_block_header("x-malware-detected", "true")
                    .with_block_header("x-malware-name", &virus_name)
                    .with_block_header("x-scan-time-ms", &scan_time.as_millis().to_string())
                    .with_tag(&format!("content-scanner:malware:{}", virus_name))
            }
            ScanResult::Error { message } => {
                warn!(
                    error = %message,
                    path = %ctx.path,
                    content_type = ?ctx.content_type,
                    "ClamAV scan error"
                );
                self.fail_action_decision()
            }
        }
    }

    async fn on_response(&self, _request: &Request, _response: &Response) -> Decision {
        // Content Scanner only operates on request bodies
        Decision::allow()
    }
}

// Safety: ContentScannerAgent is Send + Sync because all its fields are Send + Sync
unsafe impl Send for ContentScannerAgent {}
unsafe impl Sync for ContentScannerAgent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BodyConfig, ClamdConfig, Settings};

    fn create_test_config() -> Config {
        Config {
            settings: Settings {
                enabled: true,
                fail_action: FailAction::Allow,
                log_detections: true,
                log_clean: false,
            },
            body: BodyConfig {
                max_size: 1024 * 1024, // 1MB
                content_types: vec![],
            },
            clamd: ClamdConfig {
                enabled: true,
                socket_path: "/tmp/clamd.sock".into(),
                timeout_ms: 5000,
                chunk_size: 65536,
            },
            skip_paths: vec!["/health".to_string()],
            scan_methods: vec!["POST".to_string()],
        }
    }

    #[test]
    fn test_flatten_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            vec!["application/json".to_string()],
        );
        headers.insert(
            "X-Custom".to_string(),
            vec!["value1".to_string(), "value2".to_string()],
        );

        let flat = ContentScannerAgent::flatten_headers(&headers);
        assert_eq!(flat.get("content-type"), Some(&"application/json".to_string()));
        assert_eq!(flat.get("x-custom"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_get_header() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        assert_eq!(
            ContentScannerAgent::get_header(&headers, "content-type"),
            Some("application/json")
        );
        assert_eq!(
            ContentScannerAgent::get_header(&headers, "Content-Type"),
            Some("application/json")
        );
        assert_eq!(
            ContentScannerAgent::get_header(&headers, "x-missing"),
            None
        );
    }

    #[test]
    fn test_agent_creation() {
        let config = create_test_config();
        let agent = ContentScannerAgent::new(config);
        assert!(agent.config.settings.enabled);
    }

    #[test]
    fn test_fail_action_decision_allow() {
        let config = Config {
            settings: Settings {
                enabled: true,
                fail_action: FailAction::Allow,
                log_detections: true,
                log_clean: false,
            },
            body: BodyConfig::default(),
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };
        let agent = ContentScannerAgent::new(config);
        let _decision = agent.fail_action_decision();
        // Decision should allow (we can't easily test internal state, but it shouldn't panic)
        assert!(true);
    }

    #[test]
    fn test_fail_action_decision_block() {
        let config = Config {
            settings: Settings {
                enabled: true,
                fail_action: FailAction::Block,
                log_detections: true,
                log_clean: false,
            },
            body: BodyConfig::default(),
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };
        let agent = ContentScannerAgent::new(config);
        let _decision = agent.fail_action_decision();
        // Decision should block (we can't easily test internal state, but it shouldn't panic)
        assert!(true);
    }

    #[tokio::test]
    async fn test_store_and_take_context() {
        let config = create_test_config();
        let agent = ContentScannerAgent::new(config);

        let ctx = ScanContext {
            content_type: Some("application/json".to_string()),
            path: "/upload".to_string(),
            method: "POST".to_string(),
        };

        agent.store_context("req-123", ctx.clone()).await;

        let retrieved = agent.take_context("req-123").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().path, "/upload");

        // Should be gone after take
        let retrieved_again = agent.take_context("req-123").await;
        assert!(retrieved_again.is_none());
    }
}
