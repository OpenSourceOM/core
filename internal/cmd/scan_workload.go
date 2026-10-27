// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

var scanWorkloadCmd = &cobra.Command{
	Use:   "workload",
	Short: "Inventory packages on Linux root volumes",
	Long: `Inventory packages on Linux root volumes in the current account.

Each cloud is its own command: "om scan workload aws", "om scan workload azure", and "om scan workload gcp". Each runs as root on a worker in that account and region. om scan aws, om scan azure, and om scan gcp stay read-only.`,
}

func init() {
	scanCmd.AddCommand(scanWorkloadCmd)
}
