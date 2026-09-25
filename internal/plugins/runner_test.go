// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceOM/core/internal/graph"
)

func TestRunPluginBatch(t *testing.T) {
	script := writePlugin(t, `#!/bin/sh
cat <<'EOF'
{"nodes":[
  {"id":"internet:global","type":"Internet","name":"Internet","provider":"plugin"},
  {"id":"plugin:host:1","type":"Workload","name":"edge-1","provider":"plugin","properties":{"public_ip":true}}
],"edges":[
  {"source_id":"internet:global","target_id":"plugin:host:1","type":"REACHABLE"}
]}
EOF
`)
	batch, err := Run(context.Background(), script, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Nodes) != 2 || len(batch.Edges) != 1 {
		t.Fatalf("batch = %+v", batch)
	}
	if batch.Edges[0].ID == "" {
		t.Fatal("expected default edge id")
	}
	if batch.Nodes[1].Type != graph.NodeWorkload {
		t.Fatalf("type = %s", batch.Nodes[1].Type)
	}
	if batch.Nodes[1].Properties["public_ip"] != true {
		t.Fatalf("properties = %#v", batch.Nodes[1].Properties)
	}
}

func TestRunPluginFailure(t *testing.T) {
	script := writePlugin(t, "#!/bin/sh\necho 'collector exploded' >&2\nexit 1\n")
	_, err := Run(context.Background(), script, nil)
	if err == nil || !strings.Contains(err.Error(), "collector exploded") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunPluginRejectsUnknownType(t *testing.T) {
	script := writePlugin(t, `#!/bin/sh
echo '{"nodes":[{"id":"x","type":"Bucket","name":"b"}],"edges":[]}'
`)
	_, err := Run(context.Background(), script, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunPluginTimeout(t *testing.T) {
	script := writePlugin(t, "#!/bin/sh\nexec sleep 30\n")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, script, nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunRequiresExecutable(t *testing.T) {
	if _, err := Run(context.Background(), "  ", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestExampleCollectorBinary(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "example-collector")
	cmd := exec.Command("go", "build", "-o", bin, "./examples/collector")
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build example collector: %v\n%s", err, out)
	}
	batch, err := Run(context.Background(), bin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Nodes) != 3 || len(batch.Edges) != 2 {
		t.Fatalf("nodes=%d edges=%d", len(batch.Nodes), len(batch.Edges))
	}
	if batch.Edges[0].ID == "" || batch.Nodes[0].ID != graph.InternetNodeID {
		t.Fatalf("batch = %+v", batch)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func writePlugin(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin.sh")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
