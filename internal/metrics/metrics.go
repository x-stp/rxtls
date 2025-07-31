package metrics

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
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	registry           = prometheus.NewRegistry()
	defaultRegisterer  = promauto.With(registry)
	metricsInitialized sync.Once
	metricsEnabled     bool
	metricsServer      *http.Server
)

// Metrics contains all the Prometheus metrics for the application
type Metrics struct {
	// Certificate processing metrics
	CertProcessingDuration *prometheus.HistogramVec
	CertProcessedTotal     *prometheus.CounterVec
	CertFailedTotal        *prometheus.CounterVec

	// Network metrics
	NetworkRequestDuration *prometheus.HistogramVec
	NetworkRequestsTotal   *prometheus.CounterVec
	NetworkErrorsTotal     *prometheus.CounterVec
	NetworkRetriesTotal    *prometheus.CounterVec
	TLSHandshakeDuration   *prometheus.HistogramVec

	// Queue metrics
	QueueSize            *prometheus.GaugeVec
	QueueLatency         *prometheus.HistogramVec
	QueuePressure        *prometheus.GaugeVec
	QueueCapacity        *prometheus.GaugeVec
	QueueBackpressureHit *prometheus.CounterVec

	// Worker metrics
	WorkerBusy         *prometheus.GaugeVec
	WorkerProcessed    *prometheus.CounterVec
	WorkerErrors       *prometheus.CounterVec
	WorkerPanics       *prometheus.CounterVec
	WorkerIdleDuration *prometheus.HistogramVec
	WorkerRateLimit    *prometheus.GaugeVec

	// Disk I/O metrics
	DiskWriteDuration *prometheus.HistogramVec
	DiskWriteBytes    *prometheus.HistogramVec
	DiskWriteOps      *prometheus.CounterVec
	DiskErrors        *prometheus.CounterVec
	DiskBufferSize    *prometheus.GaugeVec

	// Scheduler metrics
	SchedulerShardsActive   *prometheus.GaugeVec
	SchedulerWorkSubmitted  *prometheus.CounterVec
	SchedulerWorkCompleted  *prometheus.CounterVec
	SchedulerWorkFailed     *prometheus.CounterVec
	SchedulerRateLimitDelay *prometheus.HistogramVec
	SchedulerRetriesRate    *prometheus.GaugeVec
}

// Global instance of metrics
var globalMetrics *Metrics
var metricsOnce sync.Once

// GetMetrics returns the global metrics instance
func GetMetrics() *Metrics {
	metricsOnce.Do(func() {
		globalMetrics = newMetrics()
	})
	return globalMetrics
}

// EnableMetrics enables metrics collection
func EnableMetrics() {
	metricsEnabled = true
}

// IsMetricsEnabled returns whether metrics collection is enabled
func IsMetricsEnabled() bool {
	return metricsEnabled
}

// newMetrics creates and registers all metrics
func newMetrics() *Metrics {
	buckets := []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}
	byteBuckets := []float64{1024, 10 * 1024, 50 * 1024, 100 * 1024, 500 * 1024, 1000 * 1024, 5000 * 1024, 10000 * 1024}

	m := &Metrics{
		// Certificate processing metrics
		CertProcessingDuration: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_cert_processing_duration_seconds",
				Help:    "Time spent processing certificates",
				Buckets: buckets,
			},
			[]string{"log_url", "operation"},
		),
		CertProcessedTotal: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_cert_processed_total",
				Help: "Total number of certificates processed",
			},
			[]string{"log_url", "operation", "status"},
		),
		CertFailedTotal: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_cert_failed_total",
				Help: "Total number of certificate processing failures",
			},
			[]string{"log_url", "operation", "error_type"},
		),

		// Network metrics
		NetworkRequestDuration: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_network_request_duration_seconds",
				Help:    "Time spent on network requests",
				Buckets: buckets,
			},
			[]string{"log_url", "endpoint"},
		),
		NetworkRequestsTotal: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_network_requests_total",
				Help: "Total number of network requests",
			},
			[]string{"log_url", "endpoint", "status"},
		),
		NetworkErrorsTotal: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_network_errors_total",
				Help: "Total number of network errors",
			},
			[]string{"log_url", "endpoint", "error_type"},
		),
		NetworkRetriesTotal: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_network_retries_total",
				Help: "Total number of network retries",
			},
			[]string{"log_url", "endpoint"},
		),
		TLSHandshakeDuration: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_tls_handshake_duration_seconds",
				Help:    "Time spent on TLS handshakes",
				Buckets: buckets,
			},
			[]string{"log_url"},
		),

		// Queue metrics
		QueueSize: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_queue_size",
				Help: "Current size of work queues",
			},
			[]string{"worker_id", "log_url"},
		),
		QueueLatency: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_queue_latency_seconds",
				Help:    "Time items spend in queue before processing",
				Buckets: buckets,
			},
			[]string{"worker_id", "log_url"},
		),
		QueuePressure: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_queue_pressure",
				Help: "Queue pressure as a ratio of current size to capacity (0-1)",
			},
			[]string{"worker_id", "log_url"},
		),
		QueueCapacity: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_queue_capacity",
				Help: "Maximum capacity of work queues",
			},
			[]string{"worker_id"},
		),
		QueueBackpressureHit: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_queue_backpressure_hits_total",
				Help: "Number of times backpressure was applied due to full queue",
			},
			[]string{"worker_id", "log_url"},
		),

		// Worker metrics
		WorkerBusy: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_worker_busy",
				Help: "Whether a worker is currently busy (1) or idle (0)",
			},
			[]string{"worker_id"},
		),
		WorkerProcessed: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_worker_processed_total",
				Help: "Total number of items processed by a worker",
			},
			[]string{"worker_id", "log_url"},
		),
		WorkerErrors: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_worker_errors_total",
				Help: "Total number of errors encountered by a worker",
			},
			[]string{"worker_id", "log_url", "error_type"},
		),
		WorkerPanics: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_worker_panics_total",
				Help: "Total number of panics recovered by a worker",
			},
			[]string{"worker_id"},
		),
		WorkerIdleDuration: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_worker_idle_duration_seconds",
				Help:    "Time workers spend idle waiting for work",
				Buckets: buckets,
			},
			[]string{"worker_id"},
		),
		WorkerRateLimit: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_worker_rate_limit",
				Help: "Current rate limit for each worker",
			},
			[]string{"worker_id"},
		),

		// Disk I/O metrics
		DiskWriteDuration: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_disk_write_duration_seconds",
				Help:    "Time spent writing to disk",
				Buckets: buckets,
			},
			[]string{"log_url", "operation"},
		),
		DiskWriteBytes: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_disk_write_bytes_total",
				Help:    "Total number of bytes written to disk",
				Buckets: byteBuckets,
			},
			[]string{"log_url", "operation"},
		),
		DiskWriteOps: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_disk_write_ops_total",
				Help: "Total number of write operations to disk",
			},
			[]string{"log_url", "operation"},
		),
		DiskErrors: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_disk_errors_total",
				Help: "Total number of disk errors",
			},
			[]string{"log_url", "operation", "error_type"},
		),
		DiskBufferSize: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_disk_buffer_size_bytes",
				Help: "Size of disk write buffers in bytes",
			},
			[]string{"log_url", "operation"},
		),

		// Scheduler metrics
		SchedulerShardsActive: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_scheduler_shards_active",
				Help: "Number of active shards in the scheduler",
			},
			[]string{"operation"},
		),
		SchedulerWorkSubmitted: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_scheduler_work_submitted_total",
				Help: "Total number of work items submitted to the scheduler",
			},
			[]string{"log_url", "operation"},
		),
		SchedulerWorkCompleted: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_scheduler_work_completed_total",
				Help: "Total number of work items completed by the scheduler",
			},
			[]string{"log_url", "operation"},
		),
		SchedulerWorkFailed: defaultRegisterer.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rxtls_scheduler_work_failed_total",
				Help: "Total number of work items that failed processing",
			},
			[]string{"log_url", "operation", "error_type"},
		),
		SchedulerRateLimitDelay: defaultRegisterer.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rxtls_scheduler_rate_limit_delay_seconds",
				Help:    "Time spent waiting due to rate limiting",
				Buckets: buckets,
			},
			[]string{"log_url", "operation"},
		),
		SchedulerRetriesRate: defaultRegisterer.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rxtls_scheduler_retries_rate",
				Help: "Rate of retries per second",
			},
			[]string{"log_url", "operation"},
		),
	}

	return m
}

// StartMetricsServer starts an HTTP server to expose Prometheus metrics
func StartMetricsServer(addr string) error {
	if !metricsEnabled {
		return nil
	}

	// Only start once
	var startErr error
	metricsInitialized.Do(func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

		metricsServer = &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		go func() {
			log.Printf("Starting metrics server on %s", addr)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Metrics server error: %v", err)
			}
		}()
	})

	return startErr
}

// ShutdownMetricsServer gracefully shuts down the metrics server
func ShutdownMetricsServer(ctx context.Context) error {
	if metricsServer != nil {
		log.Println("Shutting down metrics server...")
		return metricsServer.Shutdown(ctx)
	}
	return nil
}

// RecordWithLabels is a helper to record metrics with labels
func (m *Metrics) RecordWithLabels(fn func(), labels prometheus.Labels) {
	if !metricsEnabled {
		fn()
		return
	}

	start := time.Now()
	fn()
	_ = time.Since(start) // Record duration if needed
	// This is just a placeholder - actual implementation would depend on the metric type
}

// MeasureDuration is a helper to measure the duration of a function
func MeasureDuration(histogram *prometheus.HistogramVec, labels prometheus.Labels) func() {
	if !metricsEnabled {
		return func() {}
	}

	start := time.Now()
	return func() {
		duration := time.Since(start)
		histogram.With(labels).Observe(duration.Seconds())
	}
}

// UpdateQueueMetrics updates queue metrics for a worker
func (m *Metrics) UpdateQueueMetrics(workerID int, logURL string, queueSize, queueCapacity int) {
	if !metricsEnabled {
		return
	}

	m.QueueSize.WithLabelValues(string(workerID), logURL).Set(float64(queueSize))
	m.QueueCapacity.WithLabelValues(string(workerID)).Set(float64(queueCapacity))

	if queueCapacity > 0 {
		pressure := float64(queueSize) / float64(queueCapacity)
		m.QueuePressure.WithLabelValues(string(workerID), logURL).Set(pressure)
	}
}

// UpdateWorkerRateLimit updates the rate limit metric for a worker
func (m *Metrics) UpdateWorkerRateLimit(workerID int, rateLimit float64) {
	if !metricsEnabled {
		return
	}

	m.WorkerRateLimit.WithLabelValues(string(workerID)).Set(rateLimit)
}

// UpdateRetriesRate updates the retries rate metric
func (m *Metrics) UpdateRetriesRate(logURL, operation string, retriesPerSecond float64) {
	if !metricsEnabled {
		return
	}

	m.SchedulerRetriesRate.WithLabelValues(logURL, operation).Set(retriesPerSecond)
}
