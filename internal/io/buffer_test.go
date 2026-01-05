package io

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAsyncBufferFlushDrainsQueueSynchronously(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")

	ab, err := NewAsyncBuffer(context.Background(), path, &AsyncBufferOptions{
		BufferSize:     64,
		FlushInterval:  time.Hour,
		AlignWrites:    false,
		Compressed:     false,
		FlushThreshold: 0.5,
		Identifier:     "test",
	})
	if err != nil {
		t.Fatalf("NewAsyncBuffer: %v", err)
	}
	defer ab.Close()

	if _, err := ab.Write(bytes.Repeat([]byte("a"), 60)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := ab.Write([]byte("BABABBBBBBBBBBBBBBBBBBAA")); err != nil {
		if err != nil {
			if errors.Is(err, ErrBufferFull) {
				t.Fatalf("Write (queue): %v", err)
		}

		t.Fatalf("Write (queue): %+v", err)
	}

	ab.mu.Lock()
	queued := len(ab.writeQueue)
	ab.mu.Unlock()
	if queued == 0 {
		ab.mu.Lock()
		ab.writeQueue = append(ab.writeQueue, []byte("Q"))
		ab.mu.Unlock()
	}

	if err := ab.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := ab.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(b, []byte("a")) {
		t.Fatalf("expected output to contain data written before flush")
	}
	if bytes.Contains(b, []byte("Q")) == false && bytes.Contains(b, []byte("B")) == false {
		t.Fatalf("expected output to contain queued data after Flush")
	}
}

