package client

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

/*
Package client provides a configurable HTTP client for making requests to Certificate Transparency logs and other services.
It includes support for connection pooling, timeouts, and a "turbo" mode for aggressive, high-throughput scenarios.

The package manages a shared global HTTP client instance that can be configured once and then retrieved by multiple
parts of the application. This promotes reuse of TCP connections and consistent client behavior.
*/

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTP client-specific constants.
const (
	// DialTimeout is the maximum amount of time a dial will wait for a connect to complete.
	DialTimeout = 5 * time.Second
	// KeepAliveTimeout is the interval between keep-alive probes for active network connections.
	// If zero, keep-alive probes are sent with a default OS-dependent interval.
	KeepAliveTimeout = 60 * time.Second
	// RequestTimeout is the timeout for the entire HTTP request, including connection time, all redirects, and reading the response body.
	RequestTimeout = 15 * time.Second
	// MaxIdleConnsPerHost is the maximum number of idle (keep-alive) connections to keep per-host.
	MaxIdleConnsPerHost = 150 // Default value, can be overridden by Config.
)

var (
	// defaultDialTimeout specifies the default timeout for establishing a new connection.
	defaultDialTimeout = 5 * time.Second
	// defaultKeepAliveTimeout specifies the default keep-alive period for an active network connection.
	defaultKeepAliveTimeout = 60 * time.Second
	// defaultIdleConnTimeout is the maximum amount of time an idle (keep-alive) connection will remain
	// idle before closing itself.
	defaultIdleConnTimeout = 90 * time.Second
	// defaultMaxIdleConns controls the maximum number of idle (keep-alive) connections across all hosts.
	defaultMaxIdleConns = 100
	// defaultMaxConnsPerHost controls the maximum number of connections per host (includes dial, active, and idle).
	defaultMaxConnsPerHost = 100
	// defaultRequestTimeout specifies the default timeout for a complete HTTP request.
	defaultRequestTimeout = 15 * time.Second

	// sharedClient is the global HTTP client instance used by the application.
	// It is lazily initialized on first use or when explicitly configured.
	sharedClient *http.Client
	// sharedClientLock protects access to sharedClient and clientInitialized.
	sharedClientLock sync.RWMutex
	// clientInitialized indicates whether the sharedClient has been initialized.
	clientInitialized bool
)

// Config holds configuration parameters for the HTTP client.
// These settings allow tuning of connection pooling, timeouts, and other transport-level behaviors.
// A zero-value Config will result in default settings being used.
type Config struct {
	// DialTimeout is the maximum duration for establishing a new connection.
	DialTimeout time.Duration
	// KeepAliveTimeout specifies the keep-alive period for an active network connection.
	KeepAliveTimeout time.Duration
	// IdleConnTimeout is the maximum amount of time an idle (keep-alive) connection
	// will remain idle before closing itself.
	IdleConnTimeout time.Duration
	// MaxIdleConns controls the maximum number of idle (keep-alive) connections across all hosts.
	MaxIdleConns int
	// MaxIdleConnsPerHost is the maximum number of idle (keep-alive) connections to keep per host.
	MaxIdleConnsPerHost int
	// MaxConnsPerHost controls the maximum number of connections per host, including connections in the dialing,
	// active, and idle states. On limit violation, dials will block.
	MaxConnsPerHost int
	// RequestTimeout is the timeout for the entire HTTP request, including connection time,
	// all redirects, and reading the response body.
	RequestTimeout time.Duration
}

// DefaultConfig returns a new Config struct populated with default HTTP client settings.
// These defaults are sensible for general-purpose HTTP interactions but may need tuning
// for specific high-performance or constrained environments.
func DefaultConfig() *Config {
	return &Config{
		DialTimeout:      defaultDialTimeout,
		KeepAliveTimeout: defaultKeepAliveTimeout,
		IdleConnTimeout:  defaultIdleConnTimeout,
		MaxIdleConns:     defaultMaxIdleConns,
		MaxIdleConnsPerHost: MaxIdleConnsPerHost,
		MaxConnsPerHost:  defaultMaxConnsPerHost,
		RequestTimeout:   defaultRequestTimeout,
	}
}

// InitHTTPClient initializes or reconfigures the shared global HTTP client with the provided configuration.
// If a nil config is provided, it uses the default configuration obtained from DefaultConfig().
// This function is thread-safe.
//
// Note: Calling this function will replace the existing shared client, potentially affecting
// in-flight requests made with the old client if its transport was not reusable or if connections
// were specific to the old transport's settings.
func InitHTTPClient(config *Config) {
	sharedClientLock.Lock()
	defer sharedClientLock.Unlock()

	if config == nil {
		config = DefaultConfig()
	}

	// Any non zero vals coming in from e.g. ConfigureFigureMode
	// or potential libs calling this - set something; don't
	// assume.
	if config.DialTimeout == 0 {
		config.DialTimeout = defaultDialTimeout
	}
	if config.KeepAliveTimeout == 0 {
		config.KeepAliveTimeout = defaultKeepAliveTimeout
	}
	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = defaultIdleConnTimeout
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = defaultMaxIdleConns
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = MaxIdleConnsPerHost
	}
	if config.MaxConnsPerHost == 0 {
		config.MaxConnsPerHost = defaultMaxConnsPerHost
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}

	// If we're reinitializing an existing client, close idle connections on the old transport.
	// This helps avoid leaking idle keep-alive connections across reconfigs.
	if sharedClient != nil {
		if oldTransport, ok := sharedClient.Transport.(*http.Transport); ok && oldTransport != nil {
			oldTransport.CloseIdleConnections()
		}
	}

	// Configure the transport with timeouts and connection pooling options.
	// ForceAttemptHTTP2 is enabled to prefer HTTP/2 if available.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, // Respect standard proxy environment variables.
		DialContext: (&net.Dialer{
			Timeout:   config.DialTimeout,
			KeepAlive: config.KeepAliveTimeout, // Enables TCP keep-alives.
		}).DialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		MaxConnsPerHost:     config.MaxConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:  false, // Enable compression (e.g., gzip) by default.
		ForceAttemptHTTP2:   true,  // Try to use HTTP/2.
	}

	sharedClient = &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout, // Overall request timeout.
	}

	clientInitialized = true
}

// GetHTTPClient returns the shared global HTTP client instance.
// If the client has not been initialized, it will be initialized with default settings.
// This function is thread-safe.
func GetHTTPClient() *http.Client {
	sharedClientLock.RLock() // Use RLock for initial check to allow concurrent reads.
	if !clientInitialized {
		sharedClientLock.RUnlock()
		// Client not initialized, need to acquire a write lock.
		// This double-check locking pattern minimizes write lock contention.
		InitHTTPClient(nil)      // Initialize with defaults under a write lock.
		sharedClientLock.RLock() // Re-acquire read lock to safely access sharedClient.
	}
	client := sharedClient
	sharedClientLock.RUnlock()
	return client
}

// ConfigureHTTPClient provides a convenience function to update the shared HTTP client's configuration.
// It's equivalent to calling InitHTTPClient.
// This function is thread-safe.
func ConfigureHTTPClient(config *Config) {
	InitHTTPClient(config) // InitHTTPClient handles locking.
}

// ConfigureTurboMode applies a set of aggressive HTTP client settings optimized for
// high-throughput scenarios, such as massively parallel log fetching.
// This typically involves shorter dial timeouts, longer keep-alive and idle timeouts,
// and higher connection pool limits.
// This function is thread-safe.
func ConfigureTurboMode() {
	turboConfig := &Config{
		DialTimeout:      2 * time.Second,   // Faster dial attempts.
		KeepAliveTimeout: 120 * time.Second, // Keep connections alive longer.
		IdleConnTimeout:  120 * time.Second, // Allow idle connections to persist longer.
		MaxIdleConns:     500,               // Larger overall idle connection pool.
		MaxIdleConnsPerHost: 200,             // Larger per-host idle pool.
		MaxConnsPerHost:  200,               // More connections allowed per host.
		RequestTimeout:   30 * time.Second,  // Slightly longer request timeout for potentially slower turbo operations.
	}
	ConfigureHTTPClient(turboConfig)
}
