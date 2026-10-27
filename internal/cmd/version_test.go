// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandPrintsBuild(t *testing.T) {
	var out bytes.Buffer
	versionCmd.SetOut(&out)
	versionCmd.Run(versionCmd, nil)
	got := out.String()
	if !strings.Contains(got, "OpenSourceOM Core ") || !strings.Contains(got, "\ncommit ") || !strings.Contains(got, "\ndate   ") {
		t.Fatalf("output = %q", got)
	}
}
