# syntax=docker/dockerfile:1.4

# Zentinel Content Scanner Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-content-scanner-agent /zentinel-content-scanner-agent

LABEL org.opencontainers.image.title="Zentinel Content Scanner Agent" \
      org.opencontainers.image.description="Zentinel Content Scanner Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-content-scanner"

ENV RUST_LOG=info,zentinel_agent_content_scanner=debug \
    SOCKET_PATH=/var/run/zentinel/content-scanner.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-content-scanner-agent"]
