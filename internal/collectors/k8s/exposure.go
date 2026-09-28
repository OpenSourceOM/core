// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"github.com/OpenSourceOM/core/internal/graph"
	"k8s.io/apimachinery/pkg/labels"
)

type collectedPod struct {
	id     string
	labels map[string]string
}

type collectedService struct {
	id       string
	name     string
	selector map[string]string
	public   bool
}

func serviceExposesInternet(serviceType string) bool {
	return serviceType == "LoadBalancer" || serviceType == "NodePort"
}

func serviceSelectsPod(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	return labels.SelectorFromSet(selector).Matches(labels.Set(podLabels))
}

func (c *Collector) linkServicesToPods(batch *graph.Batch, pods []collectedPod, services []collectedService) {
	reachable := map[string]string{}
	for _, svc := range services {
		for _, pod := range pods {
			if !serviceSelectsPod(svc.selector, pod.labels) {
				continue
			}
			batch.Edges = append(batch.Edges, graph.Edge{
				ID:       c.edgeID(pod.id, svc.id, graph.EdgeAffects),
				SourceID: pod.id,
				TargetID: svc.id,
				Type:     graph.EdgeAffects,
				Properties: graph.MustProperties(map[string]any{
					"via": "service selector",
				}),
			})
			if svc.public && reachable[pod.id] == "" {
				reachable[pod.id] = svc.name
			}
		}
	}
	for podID, via := range reachable {
		batch.Edges = append(batch.Edges, graph.Edge{
			ID:       c.edgeID(graph.InternetNodeID, podID, graph.EdgeReachable),
			SourceID: graph.InternetNodeID,
			TargetID: podID,
			Type:     graph.EdgeReachable,
			Properties: graph.MustProperties(map[string]any{
				"via": via,
			}),
		})
	}
}
