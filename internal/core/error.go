/*
Package core provides the central logic for rxtls, including the scheduler, download manager,
and domain extractor. It defines common data structures and constants used across these components.
*/
package core

// customError is an error type that includes a retryable flag.
// This allows components to determine if an operation that resulted in this error
// should be retried.
// It implements the standard `error` interface.
type customError struct {
	message   string // The error message.
	retryable bool   // True if the error indicates a condition that might be resolved by retrying.
}

// NewError creates a new customError with the given message and retryable status.
//
// Parameters:
//   msg: The textual description of the error.
//   retryable: A boolean indicating if the error condition is potentially transient
//              and the operation could succeed on a subsequent attempt.
//
// Returns:
//   An error of type *customError.
func NewError(msg string, retryable bool) error {
	return &customError{
		message:   msg,
		retryable: retryable,
	}
}

// Error implements the standard Go `error` interface.
// It returns the textual message associated with the customError.
func (e *customError) Error() string {
	return e.message
}

// IsRetryable returns true if the error is designated as retryable, false otherwise.
// This method allows consuming code to check the retryable nature of the error
// without needing to type-assert to the concrete `customError` type if they
// are working with a standard `error` interface variable.
func (e *customError) IsRetryable() bool {
	return e.retryable
}

// IsRetryable is a helper function to check if a given error is of type *customError
// and if its retryable flag is set.
// If the error is nil, it returns false.
// If the error is not a *customError, it defaults to false (non-retryable).
//
// Parameters:
//   err: The error to check.
//
// Returns:
//   True if the error is a retryable *customError, false otherwise.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Type assert to *customError to access the IsRetryable method.
	if e, ok := err.(*customError); ok {
		return e.IsRetryable()
	}

	// If not a *customError, assume not retryable by default for unknown error types.
	return false
}

// Common error constants used within the core package.
// These provide standardized error values for frequent conditions like full queues
// or worker shutdowns, facilitating consistent error handling and checking.
var (
	// ErrQueueFull indicates that a worker's queue is at capacity and cannot accept new work items.
	// This error is typically considered retryable, as the queue might free up later.
	ErrQueueFull = NewError("queue full", true)
	// ErrWorkerShutdown indicates that a worker or the scheduler is in the process of shutting down
	// and can no longer process new work items. This is generally not a retryable error
	// in the context of the current operation, as the component is terminating.
	ErrWorkerShutdown = NewError("worker shutdown", false)
)
