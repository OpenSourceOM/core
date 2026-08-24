// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package rules

import "github.com/OpenSourceOM/core/internal/enrichment/severity"

// GraphContext captures path-aware signals used to prioritize CSPM findings.
type GraphContext struct {
	InternetReachable bool `json:"internet_reachable"`
	PathToDatastore   bool `json:"path_to_datastore"`
	AdminCanAccess    bool `json:"admin_can_access"`
}

func (c GraphContext) ScoreBoost(base int) int {
	score := base
	if c.InternetReachable {
		score += 10
	}
	if c.PathToDatastore {
		score += 15
	}
	if c.AdminCanAccess {
		score += 5
	}
	if score > 100 {
		return 100
	}
	return score
}

func SeverityFromScore(score int) string {
	switch {
	case score >= 90:
		return severity.LevelCritical
	case score >= 70:
		return severity.LevelHigh
	case score >= 50:
		return severity.LevelMedium
	case score >= 30:
		return severity.LevelLow
	default:
		return severity.LevelInfo
	}
}
