# rxtls - High-Throughput CT Log Processor

`rxtls` is a Go-based tool designed for maximum performance when downloading and processing Certificate Transparency (CT) log entries. It prioritizes raw throughput, low-level optimizations, and efficient resource utilization over idiomatic Go or portability.

**This version is optimized for Linux environments due to CPU affinity features.**

## Features

*   **High Concurrency:** Utilizes a worker pool affined to CPU cores (Linux only) for parallel processing.
*   **Memory Efficiency:** Employs `sync.Pool` for reusing work items and buffers to minimize GC pressure.
*   **Efficient Hashing:** Uses `xxh3` for fast non-cryptographic hashing.
*   **Robust Parsing:** Handles standard CT log entry framing and common certificate types (X.509, Precert TBS).
*   **Buffered I/O:** Uses buffered writers for efficient disk output.
*   **Command-Line Interface:** Structured commands via Cobra.
*   **Observability:** Optional periodic metrics display and pprof profiling support.

## Commands

*   `list`: Lists available CT logs (fetches from Google's list or local file).
    ```bash
    go run ./cmd/rxtls/main.go list [--local-logs]
    ```
*   `domains`: Extracts domain information (CN, SANs) from selected logs into per-log CSV files.
    ```bash
    # Select logs interactively
    go run ./cmd/rxtls/main.go domains -o output/domains [--metrics] [--compress] [--profile]
    ```
    Output Format: `offset,cn,primary_domain,all_domains,country,state,locality,org,issuer_cn,domain_org_hash`
*   `download`: Downloads raw certificate entries (leaf_input, extra_data) from selected logs into per-log CSV files.
    ```bash
    # Select logs interactively
    go run ./cmd/rxtls/main.go download -o output/certs [--metrics] [--compress] [--profile]
    ```
    Output Format: `offset,leaf_input_b64,extra_data_b64`

## Global Flags

*   `--local-logs`: Use `./all_logs_list.json` instead of fetching the list from Google. (Default: `true`)
*   `--profile`: Enable CPU and memory profiling. Writes `.prof` files to `/tmp/`. (Default: `false`)
*   `--metrics`: Display periodic performance metrics to stderr. (Default: `false`)

## Command-Specific Flags (`domains`, `download`)

*   `-o, --output <dir>`: Specify the output directory. Defaults differ per command (`output/domains` or `output/certs`).
*   `-c, --concurrency <int>`: Hint for concurrency level (e.g., number of parallel log setups or workers). `0` for auto. (Default: `0`)
*   `-b, --buffer <int>`: Internal buffer size for disk I/O in bytes. (Default: `262144`)
*   `--compress`: Compress output CSV files using gzip. (Default: `false`)
*   `--turbo`: (Domains only) Enable experimental high-speed mode optimizations. (NOT IMPLEMENTED) (Default: `false`)

## Building

```bash
go build -o rxtls ./cmd/rxtls/main.go
```

## Known Limitations / Future Work

*   **ASN.1 Parsing:** Still relies on standard `encoding/asn1` and `crypto/x509` which can fail on non-standard log entry variations. A more robust, potentially manual DER parser would improve compatibility.
*   **Network Optimization:** Currently uses standard `net/http` client per request. Needs replacement with a shared, tuned `http.Transport` (HTTP/2, keep-alives, pooling, socket options).
*   **io_uring:** Linux `io_uring` support for zero-copy networking is not implemented.
*   **Hashing:** DomainOrgHash still allocates for `fmt.Sprintf`. `xxh3` library used, but pre-computation or different key structure could reduce allocs.
*   **JSON Marshalling:** `ToDomainsCSVLine` uses `encoding/json` which allocates. Could be replaced with manual formatting or `strings.Builder`.
*   **Error Handling/Retries:** Retry logic in callbacks is basic.
*   **Scheduler Wait:** Mechanism for waiting for full scheduler completion could be more explicit.
*   **Turbo Mode:** Features like DNS pre-warming are not implemented.
*   **Logging:** Uses standard `log`. Should migrate to `zerolog` or `slog` for performance.
