# Content Scanner Agent

A Zentinel agent that scans uploaded files for malware using ClamAV daemon.

## Features

- **ClamAV Integration**: Connects to clamd via Unix socket using INSTREAM protocol
- **Content-Type Filtering**: Only scan specific content types (or all)
- **Path Exclusions**: Skip scanning for health checks and other paths
- **Method Filtering**: Configure which HTTP methods to scan (POST, PUT, PATCH)
- **Size Limits**: Skip scanning for bodies exceeding configured size
- **Fail-Open/Closed**: Configurable behavior when ClamAV is unavailable
- **Scan Metrics**: Headers include scan time and detection status

## Installation

```bash
cargo build --release
```

## Configuration

Create a `config.yaml` file:

```yaml
# Content Scanner Agent Configuration

settings:
  enabled: true
  fail_action: allow           # allow or block when ClamAV unavailable
  log_detections: true
  log_clean: false

# Body handling
body:
  max_size: 52428800           # 50MB max body to scan
  content_types:               # Only scan these content types (empty = all)
    - "application/octet-stream"
    - "application/zip"
    - "application/x-zip-compressed"
    - "application/gzip"
    - "application/x-gzip"
    - "application/x-tar"
    - "application/pdf"
    - "application/msword"
    - "application/vnd.openxmlformats-officedocument.*"
    - "multipart/form-data"

# ClamAV daemon configuration
clamd:
  enabled: true
  socket_path: "/var/run/clamav/clamd.ctl"
  timeout_ms: 30000            # 30 second scan timeout
  chunk_size: 65536            # 64KB chunks to clamd

# Paths to skip scanning
skip_paths:
  - "/health"
  - "/ready"
  - "/metrics"

# Methods to scan (empty = POST, PUT, PATCH)
scan_methods:
  - "POST"
  - "PUT"
  - "PATCH"
```

## Usage

```bash
# Run with default config
./zentinel-agent-content-scanner -c config.yaml

# Run with custom socket path
./zentinel-agent-content-scanner -c config.yaml -s /tmp/content-scanner.sock

# Print example configuration
./zentinel-agent-content-scanner --example-config

# Validate configuration
./zentinel-agent-content-scanner -c config.yaml --validate
```

## ClamAV Setup

The agent requires ClamAV daemon (clamd) to be running and accessible via Unix socket.

### macOS (Homebrew)

```bash
brew install clamav
# Initialize database
freshclam
# Start daemon
clamd
```

### Linux (Ubuntu/Debian)

```bash
sudo apt-get install clamav-daemon
sudo systemctl start clamav-daemon
```

### Linux (RHEL/CentOS)

```bash
sudo yum install clamav-server clamav-update
sudo freshclam
sudo systemctl start clamd@scan
```

## Response Headers

| Header | Description |
|--------|-------------|
| `x-content-scanned` | Set to `"true"` when body was scanned |
| `x-scan-time-ms` | Scan duration in milliseconds |
| `x-malware-detected` | Set to `"true"` when malware found |
| `x-malware-name` | Virus/malware signature name |
| `x-scan-skipped` | Reason scan was skipped (size-exceeded, content-type-excluded, clamd-unavailable) |

## Content-Type Matching

The agent supports flexible content-type matching:

- **Exact match**: `application/json`
- **Wildcard subtype**: `application/*` matches any application type
- **Glob suffix**: `application/vnd.*` matches `application/vnd.ms-excel`

## Testing

Test with EICAR standard antivirus test string:

```bash
# Clean file (should return 200)
echo "Hello World" | curl -X POST -H "Content-Type: application/octet-stream" -d @- http://localhost:8080/upload

# EICAR test file (should return 403)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  | curl -X POST -H "Content-Type: application/octet-stream" -d @- http://localhost:8080/upload
```

## Environment Variables

Configuration values can use environment variables with `${VAR_NAME}` syntax:

```yaml
clamd:
  socket_path: "${CLAMD_SOCKET_PATH}"
```

## License

MIT
