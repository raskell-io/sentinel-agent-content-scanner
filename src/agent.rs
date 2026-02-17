//! Content Scanner agent implementation.

use crate::clamd::{ClamdClient, ScanResult};
use crate::config::{Config, FailAction};
use async_trait::async_trait;
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason,
    HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, HeaderOp, RequestBodyChunkEvent, RequestHeadersEvent,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Metrics: total requests processed.
    requests_total: AtomicU64,
    /// Metrics: total requests blocked (malware detected).
    requests_blocked: AtomicU64,
    /// Metrics: total scan errors.
    scan_errors: AtomicU64,
    /// Metrics: total bytes scanned.
    bytes_scanned: AtomicU64,
    /// Whether the agent is draining (not accepting new requests).
    draining: Arc<RwLock<bool>>,
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
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            scan_errors: AtomicU64::new(0),
            bytes_scanned: AtomicU64::new(0),
            draining: Arc::new(RwLock::new(false)),
        }
    }

    /// Build response for fail action.
    fn fail_action_response(&self) -> AgentResponse {
        self.scan_errors.fetch_add(1, Ordering::Relaxed);
        match self.config.settings.fail_action {
            FailAction::Allow => {
                let audit = AuditMetadata {
                    tags: vec!["content-scanner:clamd-unavailable:allowed".to_string()],
                    ..Default::default()
                };
                AgentResponse::default_allow()
                    .add_request_header(HeaderOp::Set {
                        name: "x-scan-skipped".to_string(),
                        value: "clamd-unavailable".to_string(),
                    })
                    .with_audit(audit)
            }
            FailAction::Block => {
                let audit = AuditMetadata {
                    tags: vec!["content-scanner:clamd-unavailable:blocked".to_string()],
                    ..Default::default()
                };
                AgentResponse::block(503, Some("Service temporarily unavailable".to_string()))
                    .add_response_header(HeaderOp::Set {
                        name: "x-scan-error".to_string(),
                        value: "clamd-unavailable".to_string(),
                    })
                    .with_audit(audit)
            }
        }
    }

    /// Check if agent is draining.
    async fn is_draining(&self) -> bool {
        *self.draining.read().await
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
impl AgentHandlerV2 for ContentScannerAgent {
    /// Return agent capabilities for v2 protocol.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "content-scanner",
            "Content Scanner Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::RequestHeaders)
        .with_event(EventType::RequestBodyChunk)
        .with_features(AgentFeatures {
            streaming_body: true,
            websocket: false,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
            health_reporting: true,
        })
        .with_limits(AgentLimits {
            max_body_size: self.config.body.max_size,
            max_concurrency: 100,
            preferred_chunk_size: self.config.clamd.chunk_size,
            max_memory: None,
            max_processing_time_ms: Some(self.config.clamd.timeout_ms),
        })
    }

    /// Handle request headers event.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Check if draining
        if self.is_draining().await {
            debug!("Agent is draining, allowing request");
            return AgentResponse::default_allow();
        }

        // Check if scanning is enabled
        if !self.config.settings.enabled {
            debug!("Content Scanner agent disabled");
            return AgentResponse::default_allow();
        }

        // Check if ClamAV is enabled
        if !self.config.clamd.enabled {
            debug!("ClamAV scanning disabled");
            return AgentResponse::default_allow();
        }

        let method = &event.method;
        let path = &event.uri;
        let headers = Self::flatten_headers(&event.headers);

        // Check if method should be scanned
        if !self.config.should_scan_method(method) {
            debug!(method = %method, "Method not configured for scanning");
            return AgentResponse::default_allow();
        }

        // Check path exclusions
        if self.config.should_skip_path(path) {
            debug!(path = %path, "Path excluded from scanning");
            return AgentResponse::default_allow();
        }

        // Get content-type
        let content_type = Self::get_header(&headers, "content-type").map(|s| s.to_string());

        // Check if content-type should be scanned
        if !self.config.should_scan_content_type(content_type.as_deref()) {
            debug!(
                content_type = ?content_type,
                "Content-Type not configured for scanning"
            );
            return AgentResponse::default_allow()
                .add_request_header(HeaderOp::Set {
                    name: "x-scan-skipped".to_string(),
                    value: "content-type-excluded".to_string(),
                });
        }

        // Store context for body phase
        let ctx = ScanContext {
            content_type,
            path: path.to_string(),
            method: method.to_string(),
        };
        self.store_context(&event.metadata.correlation_id, ctx).await;

        debug!(
            correlation_id = %event.metadata.correlation_id,
            path = %path,
            method = %method,
            "Request marked for body scanning"
        );

        AgentResponse::default_allow()
    }

    /// Handle request body chunk event - performs the actual malware scan.
    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        // Check if we have context for this request
        let ctx = match self.take_context(&event.correlation_id).await {
            Some(c) => c,
            None => {
                // No context = not marked for scanning
                return AgentResponse::default_allow();
            }
        };

        // Decode body from base64
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let body = match STANDARD.decode(&event.data) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to decode body from base64");
                return self.fail_action_response();
            }
        };

        // Track bytes scanned
        self.bytes_scanned.fetch_add(body.len() as u64, Ordering::Relaxed);

        // Check body size
        if body.len() > self.config.body.max_size {
            debug!(
                size = body.len(),
                max_size = self.config.body.max_size,
                "Body exceeds max size, skipping scan"
            );
            let audit = AuditMetadata {
                tags: vec!["content-scanner:size-exceeded".to_string()],
                ..Default::default()
            };
            return AgentResponse::default_allow()
                .add_request_header(HeaderOp::Set {
                    name: "x-scan-skipped".to_string(),
                    value: "size-exceeded".to_string(),
                })
                .with_audit(audit);
        }

        // Scan with ClamAV
        let start = Instant::now();
        let result = match self.clamd.scan(&body).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    error = %e,
                    path = %ctx.path,
                    "ClamAV scan failed"
                );
                return self.fail_action_response();
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

                let audit = AuditMetadata {
                    tags: vec!["content-scanner:clean".to_string()],
                    ..Default::default()
                };

                AgentResponse::default_allow()
                    .add_request_header(HeaderOp::Set {
                        name: "x-content-scanned".to_string(),
                        value: "true".to_string(),
                    })
                    .add_request_header(HeaderOp::Set {
                        name: "x-scan-time-ms".to_string(),
                        value: scan_time.as_millis().to_string(),
                    })
                    .with_audit(audit)
            }
            ScanResult::Infected { virus_name } => {
                self.requests_blocked.fetch_add(1, Ordering::Relaxed);

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

                let audit = AuditMetadata {
                    tags: vec![format!("content-scanner:malware:{}", virus_name)],
                    ..Default::default()
                };

                AgentResponse::block(403, Some("Malware detected in upload".to_string()))
                    .add_response_header(HeaderOp::Set {
                        name: "x-malware-detected".to_string(),
                        value: "true".to_string(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "x-malware-name".to_string(),
                        value: virus_name.clone(),
                    })
                    .add_response_header(HeaderOp::Set {
                        name: "x-scan-time-ms".to_string(),
                        value: scan_time.as_millis().to_string(),
                    })
                    .with_audit(audit)
            }
            ScanResult::Error { message } => {
                warn!(
                    error = %message,
                    path = %ctx.path,
                    content_type = ?ctx.content_type,
                    "ClamAV scan error"
                );
                self.fail_action_response()
            }
        }
    }

    /// Return current health status.
    fn health_status(&self) -> HealthStatus {
        // Check if ClamAV is reachable
        let agent_id = "content-scanner".to_string();

        // For now, return healthy - in production, you'd want to periodically
        // check ClamAV connection and report degraded if unavailable
        HealthStatus::healthy(agent_id)
    }

    /// Return metrics report.
    fn metrics_report(&self) -> Option<MetricsReport> {
        use zentinel_agent_protocol::v2::{CounterMetric, GaugeMetric};

        let mut report = MetricsReport::new("content-scanner", 10_000);

        report.counters.push(CounterMetric::new(
            "content_scanner_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "content_scanner_requests_blocked_total",
            self.requests_blocked.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "content_scanner_scan_errors_total",
            self.scan_errors.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "content_scanner_bytes_scanned_total",
            self.bytes_scanned.load(Ordering::Relaxed),
        ));

        // Current in-flight requests (contexts waiting for body)
        let contexts_count = {
            // Use try_read to avoid blocking - if we can't get the lock, report 0
            match self.scan_contexts.try_read() {
                Ok(contexts) => contexts.len() as f64,
                Err(_) => 0.0,
            }
        };
        report.gauges.push(GaugeMetric::new(
            "content_scanner_in_flight_requests",
            contexts_count,
        ));

        Some(report)
    }

    /// Handle configuration updates from proxy.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        info!(
            config_version = ?version,
            "Received configuration update"
        );

        // Log the configuration for debugging
        debug!(config = %config, "Configuration payload");

        // In a production implementation, you would parse and apply the new config
        // For now, we accept all configurations
        true
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );

        // Set draining to stop accepting new requests
        *self.draining.write().await = true;

        // In a production implementation, you would:
        // 1. Stop accepting new requests
        // 2. Wait for in-flight requests to complete (up to grace period)
        // 3. Clean up resources
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );

        // Set draining flag
        *self.draining.write().await = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BodyConfig, ClamdConfig, Settings};
    use zentinel_agent_protocol::Decision;

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
    fn test_fail_action_response_allow() {
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
        let response = agent.fail_action_response();
        // Response should allow (decision is Allow)
        assert_eq!(response.decision, Decision::Allow);
    }

    #[test]
    fn test_fail_action_response_block() {
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
        let response = agent.fail_action_response();
        // Response should block with 503
        match response.decision {
            Decision::Block { status, .. } => assert_eq!(status, 503),
            _ => panic!("Expected Block decision"),
        }
    }

    #[test]
    fn test_capabilities() {
        let config = create_test_config();
        let agent = ContentScannerAgent::new(config);
        let caps = agent.capabilities();

        assert_eq!(caps.agent_id, "content-scanner");
        assert_eq!(caps.name, "Content Scanner Agent");
        assert!(caps.supports_event(EventType::RequestHeaders));
        assert!(caps.supports_event(EventType::RequestBodyChunk));
        assert!(caps.features.streaming_body);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
    }

    #[test]
    fn test_health_status() {
        let config = create_test_config();
        let agent = ContentScannerAgent::new(config);
        let health = agent.health_status();

        assert!(health.is_healthy());
        assert_eq!(health.agent_id, "content-scanner");
    }

    #[test]
    fn test_metrics_report() {
        let config = create_test_config();
        let agent = ContentScannerAgent::new(config);
        let report = agent.metrics_report();

        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.agent_id, "content-scanner");
        assert!(!report.counters.is_empty());
        assert!(!report.gauges.is_empty());
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
