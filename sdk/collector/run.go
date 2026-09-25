// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Collector produces one graph batch. Implementations must be read-only
// toward the systems they inventory.
type Collector interface {
	Collect(ctx context.Context) (Batch, error)
}

// Run is the plugin entrypoint. It writes a validated batch to stdout and
// exits 0, or writes an error to stderr and exits 1.
func Run(c Collector) {
	if err := writeBatch(os.Stdout, c); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func writeBatch(out io.Writer, c Collector) error {
	if c == nil {
		return fmt.Errorf("collector is nil")
	}
	batch, err := c.Collect(context.Background())
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	batch = Normalize(batch)
	if err := Validate(batch); err != nil {
		return fmt.Errorf("invalid batch: %w", err)
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(batch); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return nil
}
