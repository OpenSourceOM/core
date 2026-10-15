// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package aws

import "testing"

func TestCheckRegion(t *testing.T) {
	if err := CheckRegion("us-east-1", "us-east-1"); err != nil {
		t.Fatal(err)
	}
	err := CheckRegion("us-west-2", "us-east-1")
	if err == nil || err.Error() != "this instance is in us-west-2; set AWS_REGION=us-west-2" {
		t.Fatalf("err = %v", err)
	}
}
