# Build stage
FROM rust:1.86-slim as builder

# Install OpenSSL development packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/vibeCNI

# Copy manifests
COPY Cargo.toml .

# Create a dummy main.rs to cache dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src src/

# Build for release
RUN cargo build --release && \
    strip /usr/src/vibeCNI/target/release/vibeCNI

# Runtime stage
FROM debian:bookworm-slim

# Install required runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binary
COPY --from=builder /usr/src/vibeCNI/target/release/vibeCNI /opt/cni/bin/

# Set proper permissions for CNI binary
RUN chmod 755 /opt/cni/bin/vibeCNI

# CNI plugins don't have an entrypoint - they're executed by Kubernetes

WORKDIR /opt/cni/bin