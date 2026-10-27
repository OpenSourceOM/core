// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

var scanWorkloadCmd = &cobra.Command{
	Use:   "workload",
	Short: "Inventory packages on workload storage",
	Long: `Inventory packages on workload storage in the current account.

Root volumes are "om scan workload aws", "om scan workload azure", and "om scan workload gcp". Boot images are "om scan workload image aws", "om scan workload image azure", and "om scan workload image gcp". Each runs as root on a worker in that account and region. om scan aws, om scan azure, and om scan gcp stay read-only.`,
}

func init() {
	scanCmd.AddCommand(scanWorkloadCmd)
}
