/*
Package main is the entry point for the rxtls command-line application.

rxtls is a tool designed for interacting with Certificate Transparency (CT) logs.
Its primary functionalities include:
  - Listing available CT logs.
  - Downloading raw certificate entries (as base64 blobs) from specified CT logs.
  - Extracting domain names (Common Name and Subject Alternative Names) from certificate entries
    and saving them to CSV files.
  - Fetching and caching the official list of CT logs.

The application uses the Cobra library for command-line interface structure and flag parsing.
It leverages several internal packages:
  - `internal/certlib`: For CT log interaction logic, data models, and parsing certificate entries.
  - `internal/client`: For a configurable HTTP client used for network requests.
  - `internal/core`: For the core processing engine, including a concurrent scheduler, download manager,
    and domain extractor.
  - `internal/metrics`: For exposing Prometheus metrics for monitoring application performance.

Global flags allow users to specify options like using a local log list cache.
Subcommands (`list`, `download`, `domains`, `fetch-logs`) provide access to different functionalities,
each with its own set of specific flags for configuration (e.g., output directory, concurrency).

The main function initializes a Prometheus metrics server and then either processes a single CT log URI
(if provided directly as a flag without a subcommand) or executes the appropriate Cobra subcommand.
Graceful shutdown is handled via context cancellation triggered by OS signals (SIGINT, SIGTERM).
*/
package main

/*
rxtls — fast tool in Go for working with Certificate Transparency logs
Copyright (C) 2025  Pepijn van der Stap <rxtls@vanderstap.info>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/x-stp/rxtls/internal/certlib"
	"github.com/x-stp/rxtls/internal/client"
	"github.com/x-stp/rxtls/internal/core"
	"github.com/x-stp/rxtls/internal/metrics"
)

// Global flags (persistent across commands)
var useLocalLogs bool

// Flags specific to the download command
var (
	outputDir         string
	maxConcurrentLogs int
	bufferSize        int
	showStats         bool
	turbo             bool
	compress          bool
	downloadAll       bool
	downloadLogURLs   []string
	downloadLogsFile  string
	logsFile          string // Added for fetch-logs command
	ctURI             = flag.String("ct-uri", "", "CT log URI to process (overrides config)")
	workers           = flag.Int("workers", runtime.NumCPU(), "Number of worker goroutines")
	rateLimit         = flag.Float64("rate-limit", 100, "Initial rate limit in requests/second")
	debug             = flag.Bool("debug", false, "Enable debug logging")
	metricsPort       = flag.Int("metrics-port", 9090, "Prometheus metrics port")
)

var rootCmd = &cobra.Command{
	Use:   "rxtls",
	Short: "rxtls - A Certificate Transparency Log (domain/b64 blob) downloader and processor",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Enable local logs if requested (applies to all commands)
		if useLocalLogs {
			certlib.UseLocalLogs = true
			log.Println("Using local logs list enabled.")
		}
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available Certificate Transparency logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listLogs()
	},
}

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download certificates (full B64 blob) from selected CT logs",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Flags are parsed by Cobra and available via the variables
		return downloadLogs(outputDir, maxConcurrentLogs, bufferSize, showStats, compress, turbo)
	},
}

var domainsCmd = &cobra.Command{
	Use:   "domains",
	Short: "Extract domains from selected CT logs and save to CSV",
	Long:  `Extracts domains (CN and SANs) from certificates found in selected CT logs. Output is a CSV file per log with format: offset,cn,primary_domain,all_domains_json,country,org,issuer_cn,domain_org_hash`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Call the new core function for domain extraction
		return extractDomains(outputDir, maxConcurrentLogs, bufferSize, showStats, turbo, compress)
	},
}

var fetchLogsCmd = &cobra.Command{
	Use:   "fetch-logs",
	Short: "Fetch and save the CT logs list to a local file",
	RunE: func(cmd *cobra.Command, args []string) error {
		return fetchAndSaveLogs()
	},
}

func init() {
	// Persistent flags (available for all commands)
	rootCmd.PersistentFlags().BoolVar(&useLocalLogs, "local-logs", false, "Use local all_logs_list.json instead of fetching from internet")

	// Flags for the download command
	downloadCmd.Flags().StringVarP(&outputDir, "output", "o", "output/certs", "Output directory for certificate blobs")
	downloadCmd.Flags().IntVarP(&maxConcurrentLogs, "concurrency", "c", 0, "Maximum number of concurrent logs to process (0 for auto based on CPU)")
	downloadCmd.Flags().IntVarP(&bufferSize, "buffer", "b", core.DefaultDiskBufferSize, "Internal buffer size in bytes for disk I/O")
	downloadCmd.Flags().BoolVarP(&showStats, "stats", "s", true, "Show statistics during processing")
	downloadCmd.Flags().BoolVar(&compress, "compress", false, "Compress output CSV files")
	downloadCmd.Flags().BoolVar(&turbo, "turbo", false, "Enable high-speed mode (DNS prewarm, persistent connections)")
	downloadCmd.Flags().BoolVar(&downloadAll, "all", false, "Download from all logs (non-interactive)")
	downloadCmd.Flags().StringSliceVar(&downloadLogURLs, "log", nil, "CT log URL(s) to download from (repeatable, non-interactive)")
	downloadCmd.Flags().StringVar(&downloadLogsFile, "logs-file", "", "Path to file with CT log URLs (one per line, non-interactive)")

	// Flags for the domains command (sharing some with download)
	domainsCmd.Flags().StringVarP(&outputDir, "output", "o", "output/domains", "Output directory for domain CSV files") // Default to subfolder
	domainsCmd.Flags().IntVarP(&maxConcurrentLogs, "concurrency", "c", 0, "Maximum number of concurrent logs to process (0 for auto based on CPU)")
	domainsCmd.Flags().IntVarP(&bufferSize, "buffer", "b", 32768, "Internal buffer size in bytes")
	domainsCmd.Flags().BoolVarP(&showStats, "stats", "s", true, "Show statistics during processing")
	domainsCmd.Flags().BoolVar(&turbo, "turbo", false, "Enable high-speed mode (DNS prewarm, persistent connections)") // Added turbo flag
	domainsCmd.Flags().BoolVar(&compress, "compress", false, "Compress output CSV files")

	// Flags for the fetch-logs command
	fetchLogsCmd.Flags().StringVarP(&logsFile, "output", "o", certlib.LocalLogsFile, "Output file for CT logs list")

	// Add subcommands to the root command
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(downloadCmd)
	rootCmd.AddCommand(domainsCmd)
	rootCmd.AddCommand(fetchLogsCmd)
}

func main() {
	flag.Parse()

	// Initialize metrics
	metrics.EnableMetrics()
	if err := metrics.StartMetricsServer(fmt.Sprintf(":%d", *metricsPort)); err != nil {
		log.Printf("Failed to start metrics server: %v", err)
	}

	// Only process -ct-uri directly if specified and no cobra command is used
	if *ctURI != "" && len(os.Args) == 1 {
		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Printf("Failed to create output directory: %v", err)
			os.Exit(1)
		}

		// Create scheduler
		ctx := context.Background()
		scheduler, err := core.NewScheduler(ctx)
		if err != nil {
			log.Printf("Failed to create scheduler: %v", err)
			os.Exit(1)
		}
		defer scheduler.Shutdown()

		// Process CT log
		if err := processCTLog(ctx, *ctURI, scheduler); err != nil {
			log.Printf("Error processing CT log: %v", err)
			os.Exit(1)
		}

		// Wait for all work to complete
		scheduler.Wait()
	} else {
		// Execute cobra command
		if err := rootCmd.Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func processCTLog(ctx context.Context, uri string, scheduler *core.Scheduler) error {
	// Create log info
	logInfo := &certlib.CTLogInfo{
		URL: uri,
	}

	// Get log info
	if err := certlib.GetLogInfo(logInfo); err != nil {
		return err
	}

	// Process entries in batches
	batchSize := 1000
	for start := 0; start < int(logInfo.TreeSize); start += batchSize {
		end := min(start+batchSize, int(logInfo.TreeSize))

		// Submit work for this batch
		err := scheduler.SubmitWork(ctx, logInfo, int64(start), int64(end), func(item *core.WorkItem) error {
			// Process entries in this batch
			entries, err := certlib.DownloadEntries(ctx, logInfo, int(item.Start), int(item.End))
			if err != nil {
				return err
			}

			// Process each entry
			for _, entry := range entries.Entries {
				// Parse certificate data
				certData, err := certlib.ParseCertificateEntry(entry.LeafInput, entry.ExtraData, logInfo.URL)
				if err != nil {
					log.Printf("Error parsing certificate entry: %v", err)
					continue
				}

				// Write domains to file
				if len(certData.AllDomains) > 0 {
					// Create domains file for this batch
					domainsFile := outputDir + "/domains_" + logInfo.URL + "_" + strconv.FormatInt(item.Start, 10) + "_" + strconv.FormatInt(item.End, 10) + ".txt"
					f, err := os.OpenFile(domainsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						log.Printf("Error opening domains file: %v", err)
						continue
					}

					// Write domains
					for _, domain := range certData.AllDomains {
						if _, err := f.WriteString(domain + "\n"); err != nil {
							log.Printf("Error writing domain: %v", err)
						}
					}

					f.Close()
				}

				// Write certificate data
				if certData.AsDER != "" {
					// Create certificates file for this batch
					certsFile := outputDir + "/certs_" + logInfo.URL + "_" + strconv.FormatInt(item.Start, 10) + "_" + strconv.FormatInt(item.End, 10) + ".pem"
					f, err := os.OpenFile(certsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						log.Printf("Error opening certificates file: %v", err)
						continue
					}

					// Write certificate
					if _, err := f.WriteString("-----BEGIN CERTIFICATE-----\n"); err != nil {
						log.Printf("Error writing certificate header: %v", err)
					}
					if _, err := f.WriteString(certData.AsDER); err != nil {
						log.Printf("Error writing certificate data: %v", err)
					}
					if _, err := f.WriteString("\n-----END CERTIFICATE-----\n"); err != nil {
						log.Printf("Error writing certificate footer: %v", err)
					}

					f.Close()
				}
			}

			return nil
		})

		if err != nil {
			log.Printf("Error submitting work for batch %d-%d: %v", start, end, err)
			continue
		}
	}

	return nil
}

func listLogs() error {
	logs, err := core.ListCTLogs()
	if err != nil {
		return fmt.Errorf("error listing CT logs: %w", err)
	}

	// Display each log
	for _, logEntry := range logs { // Renamed log to logEntry to avoid conflict with log package
		fmt.Printf("%s\n", logEntry.Description)
		fmt.Printf("    \\- URL:            %s\n", logEntry.URL)
		fmt.Printf("    \\- Owner:          %s\n", logEntry.OperatedBy)
		fmt.Printf("    \\- State:          %s\n", getLogState(logEntry))
		fmt.Println()
	}

	// Print final count
	fmt.Printf("Found %d Certificate Transparency Logs\n", len(logs))
	return nil
}

func getLogState(logInfo certlib.CTLogInfo) string { // Renamed log to logInfo
	// Get log info to determine state
	if err := certlib.GetLogInfo(&logInfo); err != nil {
		return "Unknown (error getting info)"
	}

	if logInfo.TreeSize == 0 {
		return "Empty"
	}

	return fmt.Sprintf("Active (%d certificates)", logInfo.TreeSize)
}

// downloadLogs is the handler for the 'download' command.
func downloadLogs(outputDir string, maxConcurrentLogs int, bufferSize int, showStats bool, compress bool, turbo bool) error {
	log.Printf("Starting certificate download: output='%s', concurrency=%d, buffer=%d, stats=%t, compress=%t, turbo=%t",
		outputDir, maxConcurrentLogs, bufferSize, showStats, compress, turbo)

	// Initialize HTTP client with turbo mode if requested
	if turbo {
		log.Println("Enabling turbo mode for HTTP client")
		client.ConfigureTurboMode()
	}

	// 1. List logs for selection
	allLogs, err := core.ListCTLogs()
	if err != nil {
		return fmt.Errorf("error listing CT logs for selection: %w", err)
	}
	if len(allLogs) == 0 {
		return fmt.Errorf("no CT logs found to select from")
	}

	selectedLogs, err := selectLogsForDownload(allLogs)
	if err != nil {
		return err
	}
	// ----------------------------------------------

	// 3. Create and run the download manager
	log.Printf("Starting download for %d selected logs...", len(selectedLogs))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		log.Println("Interrupt received, initiating graceful shutdown...")
		cancel()
	}()

	// Create the download manager
	config := &core.DownloadConfig{
		OutputDir:         outputDir,
		BufferSize:        bufferSize,
		MaxConcurrentLogs: maxConcurrentLogs,
		CompressOutput:    compress,
	}

	// 4. Create and Run the Download Manager
	downloader, errManager := core.NewDownloadManager(ctx, config) // Renamed err to errManager
	if errManager != nil {
		return fmt.Errorf("failed to create download manager: %w", errManager)
	}

	// 5. Launch Stats Display Goroutine (if enabled)
	var statsWg sync.WaitGroup
	if showStats {
		statsWg.Add(1)
		go func() {
			defer statsWg.Done()
			displayDownloadStats(ctx, downloader) // Swapped order
		}()
	}

	// 6. Start Download Process (BLOCKING)
	if err := downloader.DownloadCertificates(selectedLogs); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, core.ErrDownloadCancelled) {
		log.Printf("Error during certificate download: %v", err)
	}
	log.Println("Main download process finished or cancelled.")

	// 7. Ensure stats goroutine finishes
	if showStats {
		log.Println("Waiting for statistics display to finish...")
		cancel() // Ensure context is cancelled
		statsWg.Wait()
	}

	// 8. Display Final Stats
	displayFinalDownloadStats(downloader)
	log.Println("Certificate download command complete.")
	return nil
}

func normalizeLogURL(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	return s
}

func selectLogsForDownload(allLogs []certlib.CTLogInfo) ([]certlib.CTLogInfo, error) {
	byURL := make(map[string]certlib.CTLogInfo, len(allLogs))
	for _, lg := range allLogs {
		byURL[normalizeLogURL(lg.URL)] = lg
	}

	var requested []string
	if downloadLogsFile != "" {
		f, err := os.Open(downloadLogsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open logs file %q: %w", downloadLogsFile, err)
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			requested = append(requested, line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("failed reading logs file %q: %w", downloadLogsFile, err)
		}
	}
	if len(downloadLogURLs) > 0 {
		requested = append(requested, downloadLogURLs...)
	}

	if downloadAll || strings.EqualFold(strings.TrimSpace(strings.Join(requested, "")), "all") {
		fmt.Println("Selected all logs for download.")
		return allLogs, nil
	}

	if len(requested) > 0 {
		selectedIndices := make(map[string]bool)
		var selected []certlib.CTLogInfo
		for _, raw := range requested {
			u := normalizeLogURL(raw)
			lg, ok := byURL[u]
			if !ok {
				return nil, fmt.Errorf("unknown log URL %q (normalized %q)", raw, u)
			}
			if !selectedIndices[u] {
				selected = append(selected, lg)
				selectedIndices[u] = true
			}
		}
		if len(selected) == 0 {
			return nil, fmt.Errorf("no valid logs selected")
		}
		fmt.Printf("Selected %d log(s) for download.\n", len(selected))
		return selected, nil
	}

	// Interactive fallback.
	fmt.Println("Available Certificate Transparency Logs:")
	for i, lg := range allLogs {
		fmt.Printf("  [%d] %s (%s)\n", i+1, lg.Description, lg.URL)
	}
	fmt.Println("  [all] Download from all logs")
	fmt.Print("Enter log number(s) to download from (e.g., 1,3,5 or all): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if strings.ToLower(input) == "all" {
		fmt.Println("Selected all logs for download.")
		return allLogs, nil
	}
	parts := strings.Split(input, ",")
	selectedIndices := make(map[int]bool)
	var selectedLogs []certlib.CTLogInfo
	for _, part := range parts {
		indexStr := strings.TrimSpace(part)
		if indexStr == "" {
			continue
		}
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 1 || index > len(allLogs) {
			return nil, fmt.Errorf("invalid input: %q is not a valid number in the range 1-%d", indexStr, len(allLogs))
		}
		if !selectedIndices[index-1] {
			selectedLogs = append(selectedLogs, allLogs[index-1])
			selectedIndices[index-1] = true
		}
	}
	if len(selectedLogs) == 0 {
		return nil, fmt.Errorf("no valid logs selected")
	}
	fmt.Printf("Selected %d log(s) for download.\n", len(selectedLogs))
	return selectedLogs, nil
}

// displayDownloadStats periodically shows download progress.
// ctx should be the first parameter for consistency with Go conventions.
func displayDownloadStats(ctx context.Context, downloader *core.DownloadManager) {
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()
	startTime := downloader.GetStats().StartTime
	log.Println("Starting download statistics display...")
	for {
		select {
		case <-ticker.C:
			stats := downloader.GetStats()
			elapsed := time.Since(startTime).Seconds()
			if elapsed < 0.1 {
				elapsed = 0.1
			}
			processedEntries := stats.ProcessedEntries.Load()
			totalEntries := stats.TotalEntries.Load()
			failedEntries := stats.FailedEntries.Load()
			entriesPerSec := float64(processedEntries) / elapsed
			percentDone := 0.0
			if totalEntries > 0 {
				percentDone = float64(processedEntries+failedEntries) / float64(totalEntries) * 100
			}
			fmt.Printf("\rProcessed: %d/%d logs | Entries: %d / ~%d (%.1f%%) | Failed: %d | Rate: %.0f ent/s | Written: %.2fMB | Retries: %.2f%%",
				stats.ProcessedLogs.Load(),
				stats.TotalLogs.Load(),
				processedEntries,
				totalEntries,
				percentDone,
				failedEntries,
				entriesPerSec,
				float64(stats.OutputBytesWritten.Load())/(1024*1024),
				stats.GetRetryRate()*100,
			)
		case <-ctx.Done():
			fmt.Println("\nDownload stats display stopping.")
			return
		}
	}
}

// displayFinalDownloadStats shows the summary download statistics.
func displayFinalDownloadStats(downloader *core.DownloadManager) {
	stats := downloader.GetStats()
	elapsed := time.Since(stats.StartTime)
	processedEntries := stats.ProcessedEntries.Load()
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(processedEntries) / elapsed.Seconds()
	}
	fmt.Println() // Ensure stats start on a new line
	fmt.Printf("\n--- Final Download Statistics ---\n")
	fmt.Printf(" Processing Time: %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("   Total Logs: %d\n", stats.TotalLogs.Load())
	fmt.Printf(" Processed Logs: %d\n", stats.ProcessedLogs.Load())
	fmt.Printf("    Failed Logs: %d\n", stats.FailedLogs.Load())
	fmt.Printf("  Total Entries: ~%d\n", stats.TotalEntries.Load())
	fmt.Printf("Processed Entries: %d (%.2f%% first try)\n",
		processedEntries,
		float64(stats.SuccessFirstTry.Load())/float64(processedEntries+1)*100) // +1 to avoid div by zero if no entries
	fmt.Printf("   Failed Entries: %d\n", stats.FailedEntries.Load())
	fmt.Printf("     Overall Rate: %.0f entries/sec\n", rate)
	fmt.Printf("       Retry Rate: %.2f%% (Total Retries: %d)\n",
		stats.GetRetryRate()*100, stats.RetryCount.Load())
	fmt.Printf("   Output Written: %.2f MB\n", float64(stats.OutputBytesWritten.Load())/(1024*1024))
	fmt.Printf("-------------------------------\n")
}

// extractDomains is the handler for the 'domains' command.
func extractDomains(outputDir string, maxConcurrentLogs int, bufferSize int, showStats bool, turbo bool, compress bool) error {
	log.Printf("Starting domain extraction: output='%s', concurrency=%d, buffer=%d, stats=%t, turbo=%t, compress=%t",
		outputDir, maxConcurrentLogs, bufferSize, showStats, turbo, compress)

	// Initialize HTTP client with turbo mode if requested
	if turbo {
		log.Println("Enabling turbo mode for HTTP client")
		client.ConfigureTurboMode()
	}

	// 1. List logs for selection (Could be made non-interactive with flags/args later)
	allLogs, err := core.ListCTLogs()
	if err != nil {
		return fmt.Errorf("error listing CT logs for selection: %w", err)
	}
	if len(allLogs) == 0 {
		return fmt.Errorf("no CT logs found to select from")
	}

	// 2. Display and prompt for selection
	fmt.Println("Available Certificate Transparency Logs:")
	for i, lg := range allLogs {
		fmt.Printf("  [%d] %s (%s)\n", i+1, lg.Description, lg.URL)
	}
	fmt.Println("  [all] Extract from all logs")
	fmt.Print("Enter log number(s) to extract domains from (e.g., 1,3,5 or all): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	var selectedLogs []certlib.CTLogInfo
	if strings.ToLower(input) == "all" {
		selectedLogs = allLogs
		fmt.Println("Selected all logs for domain extraction.")
	} else {
		parts := strings.Split(input, ",")
		selectedIndices := make(map[int]bool)
		for _, part := range parts {
			indexStr := strings.TrimSpace(part)
			if indexStr == "" {
				continue
			}
			index, err := strconv.Atoi(indexStr)
			if err != nil || index < 1 || index > len(allLogs) {
				return fmt.Errorf("invalid input: %q is not a valid number in the range 1-%d", indexStr, len(allLogs))
			}
			if !selectedIndices[index-1] {
				selectedLogs = append(selectedLogs, allLogs[index-1])
				selectedIndices[index-1] = true
			}
		}
		if len(selectedLogs) == 0 {
			return fmt.Errorf("no valid logs selected")
		}
		fmt.Printf("Selected %d log(s) for domain extraction.\n", len(selectedLogs))
	}
	// -----------------------------------------------------

	// 3. Create DomainExtractor Configuration
	config := &core.DomainExtractorConfig{
		OutputDir:         outputDir,
		BufferSize:        bufferSize,
		MaxConcurrentLogs: maxConcurrentLogs,
		Turbo:             turbo,
		CompressOutput:    compress,
	}

	// 4. Setup Context and Signal Handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is cancelled on exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to listen for signals and trigger shutdown
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, initiating shutdown...", sig)
		cancel() // Cancel context first
	}()

	// 5. Create the Domain Extractor
	extractor, errManager := core.NewDomainExtractor(ctx, config) // Renamed err
	if errManager != nil {
		return fmt.Errorf("failed to create domain extractor: %w", errManager)
	}

	// 6. Launch Stats Display Goroutine (if enabled)
	var statsWg sync.WaitGroup
	if showStats {
		statsWg.Add(1)
		go func() {
			defer statsWg.Done()
			displayDomainStats(ctx, extractor) // Swapped order
		}()
	}

	// 7. Start Domain Extraction Process (BLOCKING CALL)
	log.Printf("Starting extraction for %d selected logs...", len(selectedLogs))
	if err := extractor.ExtractDomainsToCSV(selectedLogs); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, core.ErrDownloadCancelled) {
		// Log error unless it was just context cancellation
		log.Printf("Error during domain extraction: %v", err)
	}

	// Extraction finished or was cancelled
	log.Println("Main extraction process finished or cancelled.")

	// 8. Ensure stats goroutine finishes (if started)
	if showStats {
		log.Println("Waiting for statistics display to finish...")
		// If context wasn't cancelled by signal, cancel it now to stop stats
		cancel() // Ensure context is cancelled
		statsWg.Wait()
	}

	// 9. Display Final Stats
	displayFinalDomainStats(extractor)
	log.Println("Domain extraction command complete.")
	return nil
}

// displayDomainStats periodically shows domain extraction progress.
// ctx should be the first parameter for consistency with Go conventions.
func displayDomainStats(ctx context.Context, extractor *core.DomainExtractor) {
	ticker := time.NewTicker(time.Second * 2) // Update every 2 seconds
	defer ticker.Stop()
	startTime := extractor.GetStats().StartTime

	log.Println("Starting statistics display...")

	for {
		select {
		case <-ticker.C:
			stats := extractor.GetStats()
			elapsed := time.Since(startTime).Seconds()
			if elapsed < 0.1 {
				elapsed = 0.1
			} // Avoid division by zero initially

			processedEntries := stats.ProcessedEntries.Load()
			totalEntries := stats.TotalEntries.Load()
			failedEntries := stats.FailedEntries.Load()
			entriesPerSec := float64(processedEntries) / elapsed
			percentDone := 0.0
			if totalEntries > 0 {
				// Calculate percentage based on processed + failed vs. total
				percentDone = float64(processedEntries+failedEntries) / float64(totalEntries) * 100
			}

			// Use carriage return to update the line in place
			fmt.Printf("\rProcessed: %d/%d logs | Entries: %d / ~%d (%.1f%%) | Failed: %d | Rate: %.0f ent/s | Domains: %d | Retries: %.2f%%",
				stats.ProcessedLogs.Load(),
				stats.TotalLogs.Load(),
				processedEntries,
				totalEntries,
				percentDone,
				failedEntries,
				entriesPerSec,
				stats.TotalDomainsFound.Load(),
				stats.GetRetryRate()*100, // Assuming DomainExtractorStats also gets GetRetryRate
			)
		case <-ctx.Done(): // Use the passed context
			fmt.Println("\nStats display stopping due to context cancellation.")
			return
		}
	}
}

// displayFinalDomainStats shows the summary statistics at the end.
func displayFinalDomainStats(extractor *core.DomainExtractor) {
	stats := extractor.GetStats()
	elapsed := time.Since(stats.StartTime)
	processedEntries := stats.ProcessedEntries.Load()
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(processedEntries) / elapsed.Seconds()
	}

	// Ensure the final stats appear on a new line after the progress indicator
	fmt.Println()
	fmt.Printf("\n--- Final Domain Extraction Statistics ---\n")
	fmt.Printf(" Processing Time: %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("   Total Logs: %d\n", stats.TotalLogs.Load())
	fmt.Printf(" Processed Logs: %d\n", stats.ProcessedLogs.Load())
	fmt.Printf("    Failed Logs: %d\n", stats.FailedLogs.Load())
	fmt.Printf("  Total Entries: ~%d\n", stats.TotalEntries.Load())
	fmt.Printf("Processed Entries: %d (%.2f%% first try)\n",
		processedEntries,
		float64(stats.SuccessFirstTry.Load())/float64(processedEntries+1)*100) // Assuming DomainExtractorStats has SuccessFirstTry
	fmt.Printf("   Failed Entries: %d\n", stats.FailedEntries.Load())
	fmt.Printf("   Total Domains: %d\n", stats.TotalDomainsFound.Load())
	fmt.Printf("  Overall Rate: %.0f entries/sec\n", rate)
	fmt.Printf("    Retry Rate: %.2f%% (Total Retries: %d)\n",
		stats.GetRetryRate()*100, stats.RetryCount.Load()) // Assuming DomainExtractorStats has GetRetryRate and RetryCount
	fmt.Printf("   Output Written: %.2f MB\n", float64(stats.OutputBytesWritten.Load())/(1024*1024))
	fmt.Printf("----------------------------------------\n")
}

// fetchAndSaveLogs fetches the CT logs list and saves it to a local file.
func fetchAndSaveLogs() error {
	log.Printf("Fetching CT logs list to %s...", logsFile)

	// Temporarily disable UseLocalLogs to force fetching from remote
	oldUseLocalLogs := certlib.UseLocalLogs
	certlib.UseLocalLogs = false
	defer func() { certlib.UseLocalLogs = oldUseLocalLogs }() // Ensure it's restored

	// Use the client package to fetch the logs list directly
	httpClient := client.GetHTTPClient()
	resp, err := httpClient.Get(certlib.CTLListsURL)
	if err != nil {
		return fmt.Errorf("error fetching CT logs list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error %d fetching log list (%s)", resp.StatusCode, certlib.CTLListsURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading CT logs list body: %w", err)
	}

	// Save the response to the specified file
	if err := os.WriteFile(logsFile, body, 0644); err != nil {
		return fmt.Errorf("error saving logs to file '%s': %w", logsFile, err)
	}

	log.Printf("Successfully saved CT logs list to %s", logsFile)

	// Now try to parse and count the logs from the newly saved file.
	// This also serves as a basic validation of the saved file content.
	tempOriginalLocalLogsFile := certlib.LocalLogsFile // Save original for restoration
	certlib.LocalLogsFile = logsFile                   // Temporarily point certlib to the new file
	certlib.UseLocalLogs = true                        // Force use of this local file

	logs, err := core.ListCTLogs() // This will now use the new file.
	if err != nil {
		log.Printf("Warning: Saved logs file to '%s' but encountered an error parsing it: %v", logsFile, err)
	} else {
		log.Printf("Successfully parsed %d CT logs from the saved file '%s'.", len(logs), logsFile)
	}

	// Restore the original certlib settings.
	certlib.LocalLogsFile = tempOriginalLocalLogsFile
	certlib.UseLocalLogs = oldUseLocalLogs // Restore original UseLocalLogs setting
	return nil
}

// Helper to find min of two integers (for batching end index calculation)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
