package client

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
	sharedHttpClient *http.Client
	once             sync.Once
)

// GetSharedClient initializes and returns a shared, optimized HTTP client.
func GetSharedClient() *http.Client {
	once.Do(func() {
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   DialTimeout,      // Use local constant
				KeepAlive: KeepAliveTimeout, // Use local constant
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   MaxIdleConnsPerHost, // Use local constant
			IdleConnTimeout:       KeepAliveTimeout,    // Use local constant
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		sharedHttpClient = &http.Client{
			Timeout:   RequestTimeout, // Use local constant
			Transport: transport,
		}
	})
	return sharedHttpClient
}
