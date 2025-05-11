package core

// NewError creates a new error with a message and retryable flag
func NewError(msg string, retryable bool) error {
	return &customError{
		message:   msg,
		retryable: retryable,
	}
}

// customError implements error with additional metadata
type customError struct {
	message   string
	retryable bool
}

// Error implements the error interface
func (e *customError) Error() string {
	return e.message
}

// IsRetryable returns whether the error is retryable
func (e *customError) IsRetryable() bool {
	return e.retryable
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	if e, ok := err.(*customError); ok {
		return e.IsRetryable()
	}

	return false
}

// Common error constants
var (
	ErrQueueFull      = NewError("queue full", true)
	ErrWorkerShutdown = NewError("worker shutdown", false)
)
