/*
Package core provides the central logic for rxtls, including the scheduler, download manager,
and domain extractor. It defines common data structures and constants used across these components.
*/
package core

import (
	"context"
	"time"
)

// Work defines an interface for a unit of work that can be processed.
// This interface allows for different types of tasks to be handled by a generic
// processing system (like a scheduler or worker pool) as long as they conform to this contract.
//
// Implementations of Work should encapsulate all necessary data and logic for their execution.
type Work interface {
	// Process executes the primary logic of the work unit.
	// It takes a context that can be used for cancellation or deadlines.
	// An error is returned if processing fails.
	Process(ctx context.Context) error
	// GetID returns a unique identifier for this work unit.
	// This ID can be used for logging, tracking, or sharding purposes.
	GetID() string
	// GetCreatedAt returns the timestamp when this work unit was created.
	// This can be useful for metrics, priority queuing, or staleness checks.
	GetCreatedAt() time.Time
}

// Task is a concrete implementation of the Work interface.
// It provides a flexible way to define a work unit by associating arbitrary data
// with a specific processing function (ProcessFn).
//
// Fields:
//
//	ID: A string identifier for the task.
//	CreatedAt: The time the task was created.
//	Data: An interface{} to hold any data required by the ProcessFn.
//	ProcessFn: The function that encapsulates the actual processing logic for this task.
type Task struct {
	ID        string
	CreatedAt time.Time
	Data      interface{}
	ProcessFn func(ctx context.Context, data interface{}) error
}

// Process executes the task by calling its ProcessFn with the associated context and data.
// It conforms to the Work interface.
func (t *Task) Process(ctx context.Context) error {
	return t.ProcessFn(ctx, t.Data)
}

// GetID returns the unique identifier of the task.
// It conforms to the Work interface.
func (t *Task) GetID() string {
	return t.ID
}

// GetCreatedAt returns the creation timestamp of the task.
// It conforms to the Work interface.
func (t *Task) GetCreatedAt() time.Time {
	return t.CreatedAt
}

// NewTask creates and returns a new Task instance.
//
// Parameters:
//
//	id: The unique string identifier for the new task.
//	data: The data payload to be associated with the task.
//	processFn: The function that will be called to process this task's data.
//	           This function must match the signature `func(ctx context.Context, data interface{}) error`.
//
// Returns:
//
//	A pointer to the newly created Task.
func NewTask(id string, data interface{}, processFn func(ctx context.Context, data interface{}) error) *Task {
	return &Task{
		ID:        id,
		CreatedAt: time.Now(), // Set creation time to now.
		Data:      data,
		ProcessFn: processFn,
	}
}
