// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestPodImages(t *testing.T) {
	got := podImages(corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{Image: " "},
				{Image: "busybox:1.36"},
			},
			Containers: []corev1.Container{
				{Image: "nginx:1.25.3"},
				{Image: "nginx:1.25.3"},
				{Image: "redis:7.2"},
			},
			EphemeralContainers: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Image: "debug:latest"}},
			},
		},
	})
	want := []string{"busybox:1.36", "nginx:1.25.3", "redis:7.2"}
	if len(got) != len(want) {
		t.Fatalf("images = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("images = %#v, want %#v", got, want)
		}
	}
}
