// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

// Package plugins runs external collector executables that speak the
// sdk/collector stdout protocol.
package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/OpenSourceOM/core/internal/graph"
	"github.com/OpenSourceOM/core/sdk/collector"
)

// MaxStdout is the largest graph batch a plugin may write.
const MaxStdout = 32 << 20

const maxStderr = 64 << 10

// Run executes a collector plugin and returns the graph batch from its stdout.
// args are passed through to the executable. The process inherits the
// environment and working directory of om.
func Run(ctx context.Context, executable string, args []string) (graph.Batch, error) {
	if strings.TrimSpace(executable) == "" {
		return graph.Batch{}, fmt.Errorf("plugin executable is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	cmd := exec.CommandContext(ctx, executable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return graph.Batch{}, fmt.Errorf("plugin stdout: %w", err)
	}
	var stderr cappedBuffer
	stderr.max = maxStderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return graph.Batch{}, fmt.Errorf("start plugin: %w", err)
	}

	body, readErr := io.ReadAll(io.LimitReader(stdout, MaxStdout+1))
	if len(body) > MaxStdout {
		kill(cmd)
		return graph.Batch{}, fmt.Errorf("plugin stdout exceeded %d bytes", MaxStdout)
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return graph.Batch{}, fmt.Errorf("plugin timed out: %w", ctx.Err())
	}
	if readErr != nil {
		return graph.Batch{}, fmt.Errorf("read plugin stdout: %w", readErr)
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return graph.Batch{}, fmt.Errorf("plugin failed: %w", waitErr)
		}
		return graph.Batch{}, fmt.Errorf("plugin failed: %w: %s", waitErr, msg)
	}

	var batch collector.Batch
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&batch); err != nil {
		return graph.Batch{}, fmt.Errorf("plugin stdout is not a graph batch: %w", err)
	}
	batch = collector.Normalize(batch)
	if err := collector.Validate(batch); err != nil {
		return graph.Batch{}, fmt.Errorf("plugin batch: %w", err)
	}
	return toGraph(batch), nil
}

func toGraph(batch collector.Batch) graph.Batch {
	out := graph.Batch{
		Nodes: make([]graph.Node, len(batch.Nodes)),
		Edges: make([]graph.Edge, len(batch.Edges)),
	}
	for i, node := range batch.Nodes {
		out.Nodes[i] = graph.Node{
			ID:         node.ID,
			Type:       node.Type,
			Name:       node.Name,
			Provider:   node.Provider,
			Region:     node.Region,
			AccountID:  node.AccountID,
			Properties: node.Properties,
		}
	}
	for i, edge := range batch.Edges {
		out.Edges[i] = graph.Edge{
			ID:         edge.ID,
			SourceID:   edge.SourceID,
			TargetID:   edge.TargetID,
			Type:       edge.Type,
			Properties: edge.Properties,
		}
	}
	return out
}

func kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remain := c.max - c.buf.Len()
	if remain > 0 {
		if len(p) > remain {
			_, _ = c.buf.Write(p[:remain])
		} else {
			_, _ = c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	return c.buf.String()
}
