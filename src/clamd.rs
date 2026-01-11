//! ClamAV daemon client using INSTREAM protocol.

use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Result of a ClamAV scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    /// File is clean.
    Clean,
    /// Malware detected.
    Infected {
        /// Name of the detected virus/malware.
        virus_name: String,
    },
    /// Scan error occurred.
    Error {
        /// Error message.
        message: String,
    },
}

/// Error from ClamAV operations.
#[derive(Debug)]
pub enum ClamdError {
    /// Connection to clamd failed.
    ConnectionFailed(std::io::Error),
    /// Timeout during scan.
    Timeout,
    /// I/O error during scan.
    Io(std::io::Error),
    /// Invalid response from clamd.
    InvalidResponse(String),
}

impl std::fmt::Display for ClamdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClamdError::ConnectionFailed(e) => write!(f, "Connection to clamd failed: {}", e),
            ClamdError::Timeout => write!(f, "Scan timed out"),
            ClamdError::Io(e) => write!(f, "I/O error: {}", e),
            ClamdError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
        }
    }
}

impl std::error::Error for ClamdError {}

impl From<std::io::Error> for ClamdError {
    fn from(e: std::io::Error) -> Self {
        ClamdError::Io(e)
    }
}

/// ClamAV daemon client.
pub struct ClamdClient {
    socket_path: PathBuf,
    timeout: Duration,
    chunk_size: usize,
}

impl ClamdClient {
    /// Create a new ClamAV client.
    pub fn new(socket_path: PathBuf, timeout_ms: u64, chunk_size: usize) -> Self {
        Self {
            socket_path,
            timeout: Duration::from_millis(timeout_ms),
            chunk_size,
        }
    }

    /// Scan data for malware using INSTREAM protocol.
    ///
    /// The INSTREAM protocol:
    /// 1. Send "nINSTREAM\n"
    /// 2. Send chunks as [4-byte big-endian length][data]
    /// 3. Send [0x00 0x00 0x00 0x00] to end stream
    /// 4. Read response: "stream: OK\n" or "stream: <virus> FOUND\n"
    pub async fn scan(&self, data: &[u8]) -> Result<ScanResult, ClamdError> {
        debug!(
            socket = %self.socket_path.display(),
            data_size = data.len(),
            "Starting ClamAV scan"
        );

        // Connect with timeout
        let mut stream = match timeout(self.timeout, UnixStream::connect(&self.socket_path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(ClamdError::ConnectionFailed(e)),
            Err(_) => return Err(ClamdError::Timeout),
        };

        // Send INSTREAM command
        if let Err(e) = timeout(self.timeout, stream.write_all(b"nINSTREAM\n")).await {
            warn!(error = %e, "Timeout sending INSTREAM command");
            return Err(ClamdError::Timeout);
        }

        // Send data in chunks
        for chunk in data.chunks(self.chunk_size) {
            let len = (chunk.len() as u32).to_be_bytes();

            // Send length prefix
            match timeout(self.timeout, stream.write_all(&len)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(ClamdError::Io(e)),
                Err(_) => return Err(ClamdError::Timeout),
            }

            // Send chunk data
            match timeout(self.timeout, stream.write_all(chunk)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(ClamdError::Io(e)),
                Err(_) => return Err(ClamdError::Timeout),
            }
        }

        // Send terminator (zero-length chunk)
        match timeout(self.timeout, stream.write_all(&[0u8; 4])).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ClamdError::Io(e)),
            Err(_) => return Err(ClamdError::Timeout),
        }

        // Flush the stream
        match timeout(self.timeout, stream.flush()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ClamdError::Io(e)),
            Err(_) => return Err(ClamdError::Timeout),
        }

        // Read response
        let mut response = String::new();
        match timeout(self.timeout, stream.read_to_string(&mut response)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ClamdError::Io(e)),
            Err(_) => return Err(ClamdError::Timeout),
        }

        debug!(response = %response.trim(), "ClamAV response");

        // Parse response
        parse_response(&response)
    }

    /// Check if clamd is available by sending PING.
    pub async fn ping(&self) -> Result<bool, ClamdError> {
        let mut stream = match timeout(self.timeout, UnixStream::connect(&self.socket_path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(ClamdError::ConnectionFailed(e)),
            Err(_) => return Err(ClamdError::Timeout),
        };

        // Send PING
        match timeout(self.timeout, stream.write_all(b"nPING\n")).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ClamdError::Io(e)),
            Err(_) => return Err(ClamdError::Timeout),
        }

        // Read response
        let mut response = String::new();
        match timeout(self.timeout, stream.read_to_string(&mut response)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ClamdError::Io(e)),
            Err(_) => return Err(ClamdError::Timeout),
        }

        Ok(response.trim() == "PONG")
    }

    /// Get clamd version.
    pub async fn version(&self) -> Result<String, ClamdError> {
        let mut stream = match timeout(self.timeout, UnixStream::connect(&self.socket_path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(ClamdError::ConnectionFailed(e)),
            Err(_) => return Err(ClamdError::Timeout),
        };

        // Send VERSION
        match timeout(self.timeout, stream.write_all(b"nVERSION\n")).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ClamdError::Io(e)),
            Err(_) => return Err(ClamdError::Timeout),
        }

        // Read response
        let mut response = String::new();
        match timeout(self.timeout, stream.read_to_string(&mut response)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ClamdError::Io(e)),
            Err(_) => return Err(ClamdError::Timeout),
        }

        Ok(response.trim().to_string())
    }
}

/// Parse ClamAV scan response.
///
/// Expected formats:
/// - "stream: OK\n" - file is clean
/// - "stream: <virus_name> FOUND\n" - malware detected
/// - "stream: <error> ERROR\n" - scan error
fn parse_response(response: &str) -> Result<ScanResult, ClamdError> {
    let response = response.trim();

    // Check for OK
    if response == "stream: OK" {
        return Ok(ScanResult::Clean);
    }

    // Check for FOUND (malware detected)
    if response.starts_with("stream: ") && response.ends_with(" FOUND") {
        let virus_name = response
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND"))
            .unwrap_or("Unknown")
            .to_string();
        return Ok(ScanResult::Infected { virus_name });
    }

    // Check for ERROR
    if response.starts_with("stream: ") && response.ends_with(" ERROR") {
        let message = response
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" ERROR"))
            .unwrap_or("Unknown error")
            .to_string();
        return Ok(ScanResult::Error { message });
    }

    // Unknown response format
    Err(ClamdError::InvalidResponse(response.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_clean() {
        let result = parse_response("stream: OK\n").unwrap();
        assert_eq!(result, ScanResult::Clean);
    }

    #[test]
    fn test_parse_response_infected() {
        let result = parse_response("stream: Eicar-Test-Signature FOUND\n").unwrap();
        assert_eq!(
            result,
            ScanResult::Infected {
                virus_name: "Eicar-Test-Signature".to_string()
            }
        );
    }

    #[test]
    fn test_parse_response_infected_complex_name() {
        let result = parse_response("stream: Win.Trojan.Agent-12345 FOUND\n").unwrap();
        assert_eq!(
            result,
            ScanResult::Infected {
                virus_name: "Win.Trojan.Agent-12345".to_string()
            }
        );
    }

    #[test]
    fn test_parse_response_error() {
        let result = parse_response("stream: Size limit exceeded ERROR\n").unwrap();
        assert_eq!(
            result,
            ScanResult::Error {
                message: "Size limit exceeded".to_string()
            }
        );
    }

    #[test]
    fn test_parse_response_invalid() {
        let result = parse_response("invalid response");
        assert!(result.is_err());
    }

    #[test]
    fn test_clamd_client_new() {
        let client = ClamdClient::new(
            PathBuf::from("/var/run/clamav/clamd.ctl"),
            30000,
            65536,
        );
        assert_eq!(client.socket_path, PathBuf::from("/var/run/clamav/clamd.ctl"));
        assert_eq!(client.timeout, Duration::from_millis(30000));
        assert_eq!(client.chunk_size, 65536);
    }

    #[test]
    fn test_clamd_error_display() {
        let err = ClamdError::Timeout;
        assert_eq!(format!("{}", err), "Scan timed out");

        let err = ClamdError::InvalidResponse("bad".to_string());
        assert_eq!(format!("{}", err), "Invalid response: bad");
    }
}
