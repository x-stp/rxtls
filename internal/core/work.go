package core

import (
	"context"
	"time"
)

// Work represents a unit of work to be processed
type Work interface {
	// Process executes the work
	Process(ctx context.Context) error
	// GetID returns a unique identifier for the work
	GetID() string
	// GetCreatedAt returns when the work was created
	GetCreatedAt() time.Time
}

// Task implements the Work interface
type Task struct {
	ID        string
	CreatedAt time.Time
	Data      interface{}
	ProcessFn func(ctx context.Context, data interface{}) error
}

// Process implements the Work interface
func (t *Task) Process(ctx context.Context) error {
	return t.ProcessFn(ctx, t.Data)
}

// GetID implements the Work interface
func (t *Task) GetID() string {
	return t.ID
}

// GetCreatedAt implements the Work interface
func (t *Task) GetCreatedAt() time.Time {
	return t.CreatedAt
}

// NewTask creates a new task
func NewTask(id string, data interface{}, processFn func(ctx context.Context, data interface{}) error) *Task {
	return &Task{
		ID:        id,
		CreatedAt: time.Now(),
		Data:      data,
		ProcessFn: processFn,
	}
}
