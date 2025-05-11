package core

import (
	"math"
	"sync/atomic"
	"time"
)

const (
	// MinRate is the minimum allowed rate in requests per second
	MinRate = 1.0
	// MaxRate is the maximum allowed rate in requests per second
	MaxRate = 1000.0
	// RateIncreaseStep is how much to increase the rate on success
	RateIncreaseStep = 10.0
	// RateDecreaseStep is how much to decrease the rate on failure
	RateDecreaseStep = 50.0
)

// RateLimiter implements dynamic rate limiting with backpressure
type RateLimiter struct {
	currentRate    uint64 // Stored as uint64 bits of float64
	successCount   atomic.Uint64
	failureCount   atomic.Uint64
	lastAdjustment time.Time
	backpressure   atomic.Bool
}

// NewRateLimiter creates a new rate limiter with the specified initial rate
func NewRateLimiter(initialRate float64) *RateLimiter {
	rl := &RateLimiter{
		lastAdjustment: time.Now(),
	}
	rl.setRate(initialRate)
	return rl
}

// Allow checks if a request is allowed under the current rate limit
func (rl *RateLimiter) Allow() bool {
	if rl.backpressure.Load() {
		return false
	}

	rate := rl.getRate()
	if rate <= 0 {
		return false
	}

	// Simple token bucket implementation
	now := time.Now()
	elapsed := now.Sub(rl.lastAdjustment).Seconds()
	tokens := elapsed * rate

	if tokens >= 1.0 {
		rl.lastAdjustment = now
		return true
	}

	return false
}

// RecordSuccess records a successful request and adjusts the rate
func (rl *RateLimiter) RecordSuccess() {
	rl.successCount.Add(1)
	rl.adjustRate(true)
}

// RecordFailure records a failed request and adjusts the rate
func (rl *RateLimiter) RecordFailure() {
	rl.failureCount.Add(1)
	rl.adjustRate(false)
}

// UpdateBackpressure updates the backpressure state
func (rl *RateLimiter) UpdateBackpressure(hasBackpressure bool) {
	rl.backpressure.Store(hasBackpressure)
}

// GetCurrentRate returns the current rate limit
func (rl *RateLimiter) GetCurrentRate() float64 {
	return rl.getRate()
}

// adjustRate adjusts the current rate based on success/failure
func (rl *RateLimiter) adjustRate(success bool) {
	current := rl.getRate()
	var newRate float64

	if success {
		newRate = current + RateIncreaseStep
		if newRate > MaxRate {
			newRate = MaxRate
		}
	} else {
		newRate = current - RateDecreaseStep
		if newRate < MinRate {
			newRate = MinRate
		}
	}

	rl.setRate(newRate)
}

// GetStats returns current rate limiter statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"current_rate":    rl.getRate(),
		"success_count":   rl.successCount.Load(),
		"failure_count":   rl.failureCount.Load(),
		"backpressure":    rl.backpressure.Load(),
		"last_adjustment": rl.lastAdjustment,
	}
}

// Reset resets the rate limiter to its initial state
func (rl *RateLimiter) Reset(initialRate float64) {
	rl.setRate(initialRate)
	rl.successCount.Store(0)
	rl.failureCount.Store(0)
	rl.backpressure.Store(false)
	rl.lastAdjustment = time.Now()
}

// getRate returns the current rate as a float64
func (rl *RateLimiter) getRate() float64 {
	bits := atomic.LoadUint64(&rl.currentRate)
	return math.Float64frombits(bits)
}

// setRate sets the current rate using atomic operations
func (rl *RateLimiter) setRate(rate float64) {
	bits := math.Float64bits(rate)
	atomic.StoreUint64(&rl.currentRate, bits)
}
