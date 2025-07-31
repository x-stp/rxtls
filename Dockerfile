# Build stage with multi-arch support
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS builder

# Build arguments for cross-compilation
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary for target architecture
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s" \
    -o rxtls \
    ./cmd/rxtls

# Final stage - use scratch for minimal image
FROM scratch

# Copy ca-certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /build/rxtls /usr/local/bin/rxtls

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/rxtls"]