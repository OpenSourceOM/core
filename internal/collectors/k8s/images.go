// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// podImages returns the unique container image refs on a pod, sorted.
// Init containers and app containers are included. Ephemeral containers are not.
func podImages(pod corev1.Pod) []string {
	seen := map[string]struct{}{}
	var images []string
	add := func(containers []corev1.Container) {
		for _, container := range containers {
			ref := strings.TrimSpace(container.Image)
			if ref == "" {
				continue
			}
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			images = append(images, ref)
		}
	}
	add(pod.Spec.InitContainers)
	add(pod.Spec.Containers)
	sort.Strings(images)
	return images
}
