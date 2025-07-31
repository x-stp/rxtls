/*
Package core provides the central logic for rxtls, including the scheduler, download manager,
and domain extractor. It defines common data structures and constants used across these components.
*/
package core

import (
	"math"
	"sync/atomic"
	"time"
)

// Rate limiting constants defining the behavior of the adaptive rate limiter.
const (
	// MinRate is the minimum allowed rate in requests per second (RPS).
	// The rate limiter will not decrease the rate below this value.
	MinRate = 2.0
	// MaxRate is the maximum allowed rate in requests per second (RPS).
	// The rate limiter will not increase the rate above this value.
	MaxRate = 1000.0
	// RateIncreaseStep is the additive amount by which the rate is increased upon a successful operation.
	RateIncreaseStep = 20.0
	// RateDecreaseStep is the subtractive amount by which the rate is decreased upon a failed operation
	// or when backpressure is detected.
	RateDecreaseStep = 50.0
)

// RateLimiter implements a simple adaptive rate limiting mechanism.
// It adjusts the rate based on success/failure of operations and can respond to backpressure signals.
// The current rate is stored as a float64 manipulated via atomic operations on its uint64 bit representation
// to ensure thread-safe updates without locks for `getRate` and `setRate` hot paths.
//
// This rate limiter is a basic token bucket variant where tokens are implicitly refilled based on elapsed time
// and the current rate.
//
// Concurrency: The `currentRate` is accessed atomically. `successCount`, `failureCount`,
// and `backpressure` are also atomic, making most operations non-blocking.
// `lastAdjustment` is not atomic but primarily used for calculating elapsed time in `Allow`,
// where its exact precision is less critical than overall rate control.
type RateLimiter struct {
	// currentRate stores the bit representation of the current float64 rate limit.
	// This allows for atomic load/store of the rate.
	currentRate uint64
	// successCount tracks the number of successful operations recorded.
	successCount atomic.Uint64
	// failureCount tracks the number of failed operations recorded.
	failureCount atomic.Uint64
	// lastAdjustment records the time of the last `Allow` call that consumed a token.
	// It's used to calculate token replenishment.
	lastAdjustment time.Time
	// backpressure, if true, forces the Allow method to return false, effectively halting
	// operations. This can be triggered externally (e.g., by a full queue).
	backpressure atomic.Bool
}

// NewRateLimiter creates a new RateLimiter instance with the specified initial rate.
//
// Parameters:
//
//	initialRate: The starting rate limit in requests per second (RPS).
//
// Returns:
//
//	A pointer to the newly created RateLimiter.
func NewRateLimiter(initialRate float64) *RateLimiter {
	rl := &RateLimiter{
		lastAdjustment: time.Now(), // Initialize lastAdjustment to current time.
	}
	rl.setRate(initialRate) // Set the initial rate atomically.
	return rl
}

// Allow determines if an operation should be permitted based on the current rate limit.
// It implements a simple token bucket logic: tokens are replenished over time based on `currentRate`.
// If backpressure is active, Allow will always return false.
// If the rate is zero or negative, Allow will also return false.
//
// Returns:
//
//	True if the operation is allowed, false otherwise.
//
// Hot Path: This method is expected to be called frequently and should be highly performant.
// It primarily involves atomic reads and time calculations.
func (rl *RateLimiter) Allow() bool {
	if rl.backpressure.Load() {
		return false // Backpressure is active, disallow operation.
	}

	rate := rl.getRate()
	if rate <= 0 {
		return false // Rate is zero or negative, no operations allowed.
	}

	// Simple token bucket: Calculate tokens accrued since last allowed operation.
	now := time.Now()
	elapsed := now.Sub(rl.lastAdjustment).Seconds() // Time since last token consumption.
	tokens := elapsed * rate                        // Tokens generated during elapsed time.

	if tokens >= 1.0 {
		rl.lastAdjustment = now // Consume one token by updating lastAdjustment.
		return true             // Enough tokens, allow operation.
	}

	return false // Not enough tokens.
}

// RecordSuccess is called to indicate that an operation controlled by this rate limiter was successful.
// It increments the success counter and may trigger an increase in the rate limit.
func (rl *RateLimiter) RecordSuccess() {
	rl.successCount.Add(1)
	rl.adjustRate(true) // Attempt to increase rate.
}

// RecordFailure is called to indicate that an operation controlled by this rate limiter failed.
// It increments the failure counter and may trigger a decrease in the rate limit.
func (rl *RateLimiter) RecordFailure() {
	rl.failureCount.Add(1)
	rl.adjustRate(false) // Attempt to decrease rate.
}

// UpdateBackpressure sets the backpressure state of the rate limiter.
// If `hasBackpressure` is true, the `Allow` method will subsequently return false until
// backpressure is cleared by calling UpdateBackpressure(false).
// This provides a mechanism for external components (e.g., a queue monitor) to signal the
// rate limiter to pause operations.
func (rl *RateLimiter) UpdateBackpressure(hasBackpressure bool) {
	rl.backpressure.Store(hasBackpressure)
}

// GetCurrentRate returns the current effective rate limit in requests per second.
func (rl *RateLimiter) GetCurrentRate() float64 {
	return rl.getRate()
}

// adjustRate dynamically modifies the rate limit based on the success or failure of an operation.
// If `success` is true, it attempts to increase the rate by `RateIncreaseStep`,
// capped at `MaxRate`.
// If `success` is false, it attempts to decrease the rate by `RateDecreaseStep`,
// floored at `MinRate`.
//
// This method is called internally by RecordSuccess and RecordFailure.
func (rl *RateLimiter) adjustRate(success bool) {
	current := rl.getRate()
	var newRate float64

	if success {
		newRate = current + RateIncreaseStep
		if newRate > MaxRate {
			newRate = MaxRate // Cap at maximum allowed rate.
		}
	} else {
		newRate = current - RateDecreaseStep
		if newRate < MinRate {
			newRate = MinRate // Floor at minimum allowed rate.
		}
	}

	rl.setRate(newRate) // Atomically update the rate.
}

// GetStats returns a map containing current statistics of the rate limiter.
// This is useful for monitoring and debugging the rate limiter's behavior.
// The returned map includes the current rate, total success/failure counts,
// backpressure state, and the timestamp of the last rate adjustment (token consumption).
func (rl *RateLimiter) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"current_rate":    rl.getRate(),
		"success_count":   rl.successCount.Load(),
		"failure_count":   rl.failureCount.Load(),
		"backpressure":    rl.backpressure.Load(),
		"last_adjustment": rl.lastAdjustment,
	}
}

// Reset reinitializes the rate limiter to a given initial rate and clears its statistics.
// Success/failure counts are reset, backpressure is turned off, and lastAdjustment is set to now.
//
// Parameters:
//
//	initialRate: The new initial rate limit in requests per second (RPS).
func (rl *RateLimiter) Reset(initialRate float64) {
	rl.setRate(initialRate)
	rl.successCount.Store(0)
	rl.failureCount.Store(0)
	rl.backpressure.Store(false)
	rl.lastAdjustment = time.Now()
}

// getRate atomically retrieves the current rate limit as a float64.
// It reads the uint64 bits and converts them to a float64.
func (rl *RateLimiter) getRate() float64 {
	bits := atomic.LoadUint64(&rl.currentRate)
	return math.Float64frombits(bits)
}

// setRate atomically sets the current rate limit.
// It converts the float64 rate to its uint64 bit representation for atomic storage.
func (rl *RateLimiter) setRate(rate float64) {
	bits := math.Float64bits(rate)
	atomic.StoreUint64(&rl.currentRate, bits)
}
