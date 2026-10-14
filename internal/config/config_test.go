// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"
)

func TestServeAutoMigrateDefaultsWhenUnset(t *testing.T) {
	t.Setenv("OM_AUTO_MIGRATE", "false")
	if err := os.Unsetenv("OM_AUTO_MIGRATE"); err != nil {
		t.Fatal(err)
	}

	got, err := ServeAutoMigrate()
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("unset OM_AUTO_MIGRATE should apply migrations")
	}
}

func TestServeAutoMigrate(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    bool
		wantErr bool
	}{
		{name: "empty", value: "  ", want: true},
		{name: "true", value: "true", want: true},
		{name: "false", value: "false", want: false},
		{name: "zero", value: "0", want: false},
		{name: "junk", value: "sometimes", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OM_AUTO_MIGRATE", tt.value)
			got, err := ServeAutoMigrate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ServeAutoMigrate: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ServeAutoMigrate() = %v, want %v", got, tt.want)
			}
		})
	}
}
