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
	Run: func(cmd *cobra.Command, args []string) {
		listLogs()
	},
}

var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download certificates (full B64 blob) from selected CT logs",
	Run: func(cmd *cobra.Command, args []string) {
		// Flags are parsed by Cobra and available via the variables
		downloadLogs(outputDir, maxConcurrentLogs, bufferSize, showStats, compress, turbo)
	},
}

var domainsCmd = &cobra.Command{
	Use:   "domains",
	Short: "Extract domains from selected CT logs and save to CSV",
	Long:  `Extracts domains (CN and SANs) from certificates found in selected CT logs. Output is a CSV file per log with format: offset,cn,primary_domain,all_domains_json,country,org,issuer_cn,domain_org_hash`,
	Run: func(cmd *cobra.Command, args []string) {
		// Call the new core function for domain extraction
		extractDomains(outputDir, maxConcurrentLogs, bufferSize, showStats, turbo, compress)
	},
}

var fetchLogsCmd = &cobra.Command{
	Use:   "fetch-logs",
	Short: "Fetch and save the CT logs list to a local file",
	Run: func(cmd *cobra.Command, args []string) {
		fetchAndSaveLogs()
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
		log.Fatalf("Failed to start metrics server: %v", err)
	}

	// Only process -ct-uri directly if specified and no cobra command is used
	if *ctURI != "" && len(os.Args) == 1 {
		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Fatalf("Failed to create output directory: %v", err)
		}

		// Create scheduler
		ctx := context.Background()
		scheduler, err := core.NewScheduler(ctx)
		if err != nil {
			log.Fatalf("Failed to create scheduler: %v", err)
		}
		defer scheduler.Shutdown()

		// Process CT log
		if err := processCTLog(*ctURI, scheduler); err != nil {
			log.Fatalf("Error processing CT log: %v", err)
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

func processCTLog(uri string, scheduler *core.Scheduler) error {
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
		err := scheduler.SubmitWork(context.Background(), logInfo, int64(start), int64(end), func(item *core.WorkItem) error {
			// Process entries in this batch
			entries, err := certlib.DownloadEntries(context.Background(), logInfo, int(item.Start), int(item.End))
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

func listLogs() {
	logs, err := core.ListCTLogs()
	if err != nil {
		log.Fatalf("Error listing CT logs: %v", err)
	}

	// Display each log
	for _, log := range logs {
		fmt.Printf("%s\n", log.Description)
		fmt.Printf("    \\- URL:            %s\n", log.URL)
		fmt.Printf("    \\- Owner:          %s\n", log.OperatedBy)
		fmt.Printf("    \\- State:          %s\n", getLogState(log))
		fmt.Println()
	}

	// Print final count
	fmt.Printf("Found %d Certificate Transparency Logs\n", len(logs))
}

func getLogState(log certlib.CTLogInfo) string {
	// Get log info to determine state
	if err := certlib.GetLogInfo(&log); err != nil {
		return "Unknown (error getting info)"
	}

	if log.TreeSize == 0 {
		return "Empty"
	}

	return fmt.Sprintf("Active (%d certificates)", log.TreeSize)
}

// downloadLogs is the handler for the 'download' command.
func downloadLogs(outputDir string, maxConcurrentLogs int, bufferSize int, showStats bool, compress bool, turbo bool) {
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
		log.Fatalf("Error listing CT logs for selection: %v", err)
	}
	if len(allLogs) == 0 {
		log.Fatalf("No CT logs found to select from.")
	}

	// 2. Display and prompt for selection
	fmt.Println("Available Certificate Transparency Logs:")
	for i, lg := range allLogs {
		fmt.Printf("  [%d] %s (%s)\n", i+1, lg.Description, lg.URL)
	}
	fmt.Println("  [all] Download from all logs")
	fmt.Print("Enter log number(s) to download from (e.g., 1,3,5 or all): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	var selectedLogs []certlib.CTLogInfo
	if strings.ToLower(input) == "all" {
		selectedLogs = allLogs
		fmt.Println("Selected all logs for download.")
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
				log.Fatalf("Invalid input: %q is not a valid number in the range 1-%d", indexStr, len(allLogs))
			}
			if !selectedIndices[index-1] {
				selectedLogs = append(selectedLogs, allLogs[index-1])
				selectedIndices[index-1] = true
			}
		}
		if len(selectedLogs) == 0 {
			log.Fatalf("No valid logs selected.")
		}
		fmt.Printf("Selected %d log(s) for download.\n", len(selectedLogs))
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
	downloader, err := core.NewDownloadManager(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create download manager: %v", err)
	}

	// 5. Launch Stats Display Goroutine (if enabled)
	var statsWg sync.WaitGroup
	if showStats {
		statsWg.Add(1)
		go func() {
			defer statsWg.Done()
			displayDownloadStats(downloader, ctx)
		}()
	}

	// 6. Start Download Process (BLOCKING)
	err = downloader.DownloadCertificates(selectedLogs)
	if err != nil && !errors.Is(err, context.Canceled) {
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
}

// displayDownloadStats periodically shows download progress.
func displayDownloadStats(downloader *core.DownloadManager, ctx context.Context) {
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
			fmt.Printf("\rProcessed: %d/%d logs | Entries: %d / ~%d (%.1f%%) | Failed: %d | Rate: %.0f ent/s | Written: %.2fMB",
				stats.ProcessedLogs.Load(),
				stats.TotalLogs.Load(),
				processedEntries,
				totalEntries,
				percentDone,
				failedEntries,
				entriesPerSec,
				float64(stats.OutputBytesWritten.Load())/(1024*1024),
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
	fmt.Println()
	fmt.Printf("\n--- Final Download Statistics ---\n")
	fmt.Printf(" Processing Time: %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("   Total Logs: %d\n", stats.TotalLogs.Load())
	fmt.Printf(" Processed Logs: %d\n", stats.ProcessedLogs.Load())
	fmt.Printf("    Failed Logs: %d\n", stats.FailedLogs.Load())
	fmt.Printf("  Total Entries: ~%d\n", stats.TotalEntries.Load())
	fmt.Printf("Processed Entries: %d\n", processedEntries)
	fmt.Printf("   Failed Entries: %d\n", stats.FailedEntries.Load())
	fmt.Printf("   Output Written: %.2f MB\n", float64(stats.OutputBytesWritten.Load())/(1024*1024))
	fmt.Printf("     Average Rate: %.0f entries/sec\n", rate)
	fmt.Printf("-------------------------------\n")
}

// extractDomains is the handler for the 'domains' command.
func extractDomains(outputDir string, maxConcurrentLogs int, bufferSize int, showStats bool, turbo bool, compress bool) {
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
		log.Fatalf("Error listing CT logs for selection: %v", err)
	}
	if len(allLogs) == 0 {
		log.Fatalf("No CT logs found to select from.")
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
				log.Fatalf("Invalid input: %q is not a valid number in the range 1-%d", indexStr, len(allLogs))
			}
			if !selectedIndices[index-1] {
				selectedLogs = append(selectedLogs, allLogs[index-1])
				selectedIndices[index-1] = true
			}
		}
		if len(selectedLogs) == 0 {
			log.Fatalf("No valid logs selected.")
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
		// TODO: Need a way to signal the extractor to shutdown gracefully beyond just context.
		// extractor.Shutdown() // This would ideally be called here if available
	}()

	// 5. Create the Domain Extractor
	extractor, err := core.NewDomainExtractor(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create domain extractor: %v", err)
	}

	// 6. Launch Stats Display Goroutine (if enabled)
	var statsWg sync.WaitGroup
	if showStats {
		statsWg.Add(1)
		go func() {
			defer statsWg.Done()
			displayDomainStats(extractor, ctx) // Pass extractor's context
		}()
	}

	// 7. Start Domain Extraction Process (BLOCKING CALL)
	log.Printf("Starting extraction for %d selected logs...", len(selectedLogs))
	err = extractor.ExtractDomainsToCSV(selectedLogs)
	if err != nil && !errors.Is(err, context.Canceled) {
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
}

// displayDomainStats periodically shows domain extraction progress.
func displayDomainStats(extractor *core.DomainExtractor, ctx context.Context) {
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
			fmt.Printf("\rProcessed: %d/%d logs | Entries: %d / ~%d (%.1f%%) | Failed: %d | Rate: %.0f ent/s | Domains: %d",
				stats.ProcessedLogs.Load(),
				stats.TotalLogs.Load(),
				processedEntries,
				totalEntries,
				percentDone,
				failedEntries,
				entriesPerSec,
				stats.TotalDomainsFound.Load(),
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
	fmt.Printf("Processed Entries: %d\n", processedEntries)
	fmt.Printf("   Failed Entries: %d\n", stats.FailedEntries.Load())
	fmt.Printf("   Total Domains: %d\n", stats.TotalDomainsFound.Load())
	fmt.Printf("   Output Written: %.2f MB\n", float64(stats.OutputBytesWritten.Load())/(1024*1024))
	fmt.Printf("     Average Rate: %.0f entries/sec\n", rate)
	fmt.Printf("----------------------------------------\n")
}

// Commented out old/unused stats functions
/*
func displayStats(engine *core.Engine) { ... }
func displayFinalStats(engine *core.Engine) { ... }
*/

// fetchAndSaveLogs fetches the CT logs list and saves it to a local file.
func fetchAndSaveLogs() {
	log.Printf("Fetching CT logs list to %s...", logsFile)

	// Temporarily disable UseLocalLogs to force fetching from remote
	oldUseLocalLogs := certlib.UseLocalLogs
	certlib.UseLocalLogs = false

	// Use the client package to fetch the logs list directly
	httpClient := client.GetHTTPClient()
	resp, err := httpClient.Get(certlib.CTLListsURL)
	if err != nil {
		log.Fatalf("Error fetching CT logs list: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("HTTP error %d fetching log list", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading CT logs list body: %v", err)
	}

	// Save the response to the specified file
	if err := os.WriteFile(logsFile, body, 0644); err != nil {
		log.Fatalf("Error saving logs to file: %v", err)
	}

	log.Printf("Successfully saved CT logs list to %s", logsFile)

	// Now try to parse and count the logs
	tempLocalLogsFile := certlib.LocalLogsFile
	certlib.LocalLogsFile = logsFile
	certlib.UseLocalLogs = true
	logs, err := core.ListCTLogs()
	if err != nil {
		log.Printf("Warning: Saved logs file but had error parsing it: %v", err)
	} else {
		log.Printf("Successfully parsed %d CT logs from the saved file", len(logs))
	}

	// Restore the original values
	certlib.UseLocalLogs = oldUseLocalLogs
	certlib.LocalLogsFile = tempLocalLogsFile
}
