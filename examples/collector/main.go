// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

// Command collector is a sample OpenSourceOM plugin.
//
//	go build -o example-collector ./examples/collector
//	om scan plugin -- ./example-collector
package main

import (
	"context"

	"github.com/OpenSourceOM/core/sdk/collector"
)

func main() {
	collector.Run(example{})
}

type example struct{}

func (example) Collect(context.Context) (collector.Batch, error) {
	return Sample(), nil
}

// Sample is a tiny external inventory: an internet-reachable host that can
// reach a public object store. It shows the batch shape plugins must emit.
func Sample() collector.Batch {
	return collector.Batch{
		Nodes: []collector.Node{
			{
				ID:       collector.InternetNodeID,
				Type:     collector.NodeInternet,
				Name:     "Internet",
				Provider: "plugin",
			},
			{
				ID:       "plugin:host:edge-1",
				Type:     collector.NodeWorkload,
				Name:     "edge-1",
				Provider: "plugin",
				Properties: map[string]any{
					"public_ip": true,
				},
			},
			{
				ID:       "plugin:bucket:logs",
				Type:     collector.NodeDatastore,
				Name:     "plugin-logs",
				Provider: "plugin",
				Properties: map[string]any{
					"public_access": true,
					"encryption":    false,
				},
			},
		},
		Edges: []collector.Edge{
			{
				SourceID: collector.InternetNodeID,
				TargetID: "plugin:host:edge-1",
				Type:     collector.EdgeReachable,
			},
			{
				SourceID: "plugin:host:edge-1",
				TargetID: "plugin:bucket:logs",
				Type:     collector.EdgeCanAccess,
			},
		},
	}
}
