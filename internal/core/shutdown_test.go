package core

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadManagerShutdownFlushesAndRenamesEvenIfContextCanceled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tmp := filepath.Join(dir, "out.csv.tmp")
	final := filepath.Join(dir, "out.csv")

	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	w := bufio.NewWriterSize(f, 64)
	if _, err := w.WriteString("hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	parent := context.Background()
	ctx, cancel := context.WithCancel(parent)
	cancel() // simulates signal/parent cancellation prior to callign Shutdown()

	dm := &DownloadManager{
		ctx:    ctx,
		cancel: func() {},
	}
	dm.setupComplete.Store(true)
	dm.outputMap.Store("k", &lockedWriter{
		writer:    w,
		file:      f,
		filePath:  tmp,
		finalPath: final,
	})

	dm.Shutdown()

	if _, err := os.Stat(final); err != nil {
		t.Fatalf("expected final file to exist: %v", err)
	}
	if _, err := os.Stat(tmp); err == nil {
		t.Fatalf("expected temp file to be renamed away")
	}
	b, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if string(b) != "hello\n" {
		t.Fatalf("unexpected content: %q", string(b))
	}
}

func TestDomainExtractorShutdownFlushesAndRenamesEvenIfContextCanceled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tmp := filepath.Join(dir, "out.csv.tmp")
	final := filepath.Join(dir, "out.csv")

	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	w := bufio.NewWriterSize(f, 64)
	if _, err := w.WriteString("hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}

	parent := context.Background()
	ctx, cancel := context.WithCancel(parent)
	cancel()

	de := &DomainExtractor{
		ctx:    ctx,
		cancel: func() {},
	}
	de.setupComplete.Store(true)
	de.outputMap.Store("k", &lockedWriter{
		writer:    w,
		file:      f,
		filePath:  tmp,
		finalPath: final,
	})

	de.Shutdown()

	if _, err := os.Stat(final); err != nil {
		t.Fatalf("expected final file to exist: %v", err)
	}
	if _, err := os.Stat(tmp); err == nil {
		t.Fatalf("expected temp file to be renamed away")
	}
	b, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if string(b) != "hello\n" {
		t.Fatalf("unexpected content: %q", string(b))
	}
}

