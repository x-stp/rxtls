# rxtls - High-Performance Certificate Transparency Processor

rxtls is a high-throughput, fault-tolerant Certificate Transparency log processor designed for hyperscale environments. It provides efficient processing of CT logs with dynamic backpressure handling, adaptive rate limiting, and comprehensive observability.

## Features

- **High Throughput**: Process CT logs efficiently with a worker pool architecture
- **Fault Tolerance**: Automatic retries, backpressure handling, and graceful shutdown
- **Dynamic Rate Limiting**: Adaptive rate control based on success/failure patterns
- **Observability**: Prometheus metrics for monitoring and alerting
- **Configurable**: CLI flags for customizing behavior and CT log sources
- **Versatile**: Download raw certificates or extract domains from CT logs

## Architecture

The system consists of several key components:

### Scheduler
- Manages a pool of workers
- Distributes work using least-loaded worker selection
- Implements graceful shutdown
- Provides statistics and metrics

### Workers
- Process work items from their queues
- Implement backpressure handling
- Track success/failure metrics
- Support CPU affinity for optimal performance

### Rate Limiter
- Dynamic rate adjustment based on success/failure
- Token bucket implementation for smooth rate limiting
- Backpressure integration
- Atomic operations for thread safety

### Metrics
- Prometheus integration for monitoring
- Queue pressure tracking
- Success/failure rate monitoring
- Resource utilization metrics

## Usage

The tool provides several subcommands:

```bash
# List available CT logs
rxtls list

# Download certificates from CT logs
rxtls download

# Extract domains from certificates in CT logs
rxtls domains

# Fetch and save the CT logs list to a local file
rxtls fetch-logs

# Direct processing with URI (legacy mode)
rxtls --ct-uri https://ct.example.com/log
```

### Global Flags

```bash
# Use local logs list instead of fetching from internet
rxtls --local-logs [command]

# Customize worker pool size
rxtls --workers 8

# Set initial rate limit
rxtls --rate-limit 1000

# Enable debug logging
rxtls --debug

# Configure Prometheus metrics port
rxtls --metrics-port 9090
```

### Download Command

```bash
# Basic download with interactive log selection
rxtls download

# Specify output directory
rxtls download --output /path/to/output

# Configure concurrency
rxtls download --concurrency 10

# Adjust buffer size
rxtls download --buffer 262144

# Enable compression
rxtls download --compress

# Enable high-speed mode
rxtls download --turbo
```

### Domains Command

```bash
# Basic domain extraction with interactive log selection
rxtls domains

# Specify output directory
rxtls domains --output /path/to/domains

# Configure concurrency
rxtls domains --concurrency 10

# Adjust buffer size
rxtls domains --buffer 32768

# Enable compression
rxtls domains --compress

# Enable high-speed mode
rxtls domains --turbo
```

## Configuration

### CLI Flags

- `--ct-uri`: CT log URI to process (default: from config)
- `--workers`: Number of worker goroutines (default: runtime.NumCPU())
- `--rate-limit`: Initial rate limit in requests/second (default: 100)
- `--debug`: Enable debug logging
- `--metrics-port`: Prometheus metrics port (default: 9090)
- `--local-logs`: Use local logs list instead of fetching from internet

### Environment Variables

- `RXTLS_CONFIG`: Path to config file
- `RXTLS_LOG_LEVEL`: Log level (debug, info, warn, error)
- `RXTLS_METRICS_PORT`: Prometheus metrics port

## Metrics

The following Prometheus metrics are exposed:

- `rxtls_worker_queue_size`: Current size of worker queues
- `rxtls_worker_queue_pressure`: Queue pressure (0-1)
- `rxtls_worker_processed_total`: Total processed items
- `rxtls_worker_errors_total`: Total errors
- `rxtls_rate_limit_current`: Current rate limit
- `rxtls_rate_limit_success_total`: Total successful requests
- `rxtls_rate_limit_failure_total`: Total failed requests

## Development

### Prerequisites

- Go 1.21 or later
- Make (optional, for build scripts)

### Building

```bash
# Build binary
go build

# Run tests
go test ./...

# Run benchmarks
go test -bench=. ./...
```

### Testing

The codebase includes comprehensive tests:

- Unit tests for all components
- Integration tests for the full pipeline
- Benchmarks for performance testing
- Race condition detection enabled

## License

GNU Affero General Public License v3 - see LICENSE file for details
