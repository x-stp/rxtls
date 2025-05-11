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

import (
	"net"
	"net/http"
	"sync"
	"time"
	// "rxtls/internal/core" // No longer needed
)

// Define needed constants locally for the client
const (
	DialTimeout         = 5 * time.Second
	KeepAliveTimeout    = 60 * time.Second
	RequestTimeout      = 15 * time.Second
	MaxIdleConnsPerHost = 100 // Default value
)

var (
	// Default client settings
	defaultDialTimeout      = 5 * time.Second
	defaultKeepAliveTimeout = 60 * time.Second
	defaultIdleConnTimeout  = 90 * time.Second
	defaultMaxIdleConns     = 100
	defaultMaxConnsPerHost  = 10
	defaultRequestTimeout   = 15 * time.Second

	// Shared client instance with mutex for config updates
	sharedClient      *http.Client
	sharedClientLock  sync.RWMutex
	clientInitialized bool
)

// ClientConfig holds configuration for the HTTP client
type ClientConfig struct {
	DialTimeout      time.Duration
	KeepAliveTimeout time.Duration
	IdleConnTimeout  time.Duration
	MaxIdleConns     int
	MaxConnsPerHost  int
	RequestTimeout   time.Duration
}

// DefaultClientConfig returns the default HTTP client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		DialTimeout:      defaultDialTimeout,
		KeepAliveTimeout: defaultKeepAliveTimeout,
		IdleConnTimeout:  defaultIdleConnTimeout,
		MaxIdleConns:     defaultMaxIdleConns,
		MaxConnsPerHost:  defaultMaxConnsPerHost,
		RequestTimeout:   defaultRequestTimeout,
	}
}

// InitHTTPClient initializes the shared HTTP client with the given configuration
func InitHTTPClient(config *ClientConfig) {
	sharedClientLock.Lock()
	defer sharedClientLock.Unlock()

	if config == nil {
		config = DefaultClientConfig()
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   config.DialTimeout,
			KeepAlive: config.KeepAliveTimeout,
		}).DialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	sharedClient = &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
	}

	clientInitialized = true
}

// GetHTTPClient returns the shared HTTP client, initializing it with default settings if needed
func GetHTTPClient() *http.Client {
	sharedClientLock.RLock()
	if !clientInitialized {
		sharedClientLock.RUnlock()
		InitHTTPClient(nil) // Initialize with defaults
		sharedClientLock.RLock()
	}
	client := sharedClient
	sharedClientLock.RUnlock()
	return client
}

// ConfigureHTTPClient updates the HTTP client configuration
func ConfigureHTTPClient(config *ClientConfig) {
	InitHTTPClient(config) // This will lock and update the client
}

// ConfigureTurboMode sets aggressive HTTP client settings for maximum throughput
func ConfigureTurboMode() {
	turboConfig := &ClientConfig{
		DialTimeout:      2 * time.Second,
		KeepAliveTimeout: 120 * time.Second,
		IdleConnTimeout:  120 * time.Second,
		MaxIdleConns:     500,
		MaxConnsPerHost:  50,
		RequestTimeout:   30 * time.Second,
	}
	ConfigureHTTPClient(turboConfig)
}
