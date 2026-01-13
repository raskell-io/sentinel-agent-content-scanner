# syntax=docker/dockerfile:1.4

# Sentinel Content Scanner Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-agent-content-scanner /sentinel-agent-content-scanner

LABEL org.opencontainers.image.title="Sentinel Content Scanner Agent" \
      org.opencontainers.image.description="Sentinel Content Scanner Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-content-scanner"

ENV RUST_LOG=info,sentinel_agent_content_scanner=debug \
    SOCKET_PATH=/var/run/sentinel/content-scanner.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-agent-content-scanner"]
