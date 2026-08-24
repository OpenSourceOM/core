// Copyright 2026 OpenSourceOM
// SPDX-License-Identifier: Apache-2.0

package severity

import "strings"

const (
	LevelCritical = "critical"
	LevelHigh     = "high"
	LevelMedium   = "medium"
	LevelLow      = "low"
	LevelInfo     = "info"
)

// FromCVSS maps a CVSS base score (0–10) to a normalized severity level and score (0–100).
func FromCVSS(score float64) (level string, normalized int) {
	switch {
	case score >= 9.0:
		return LevelCritical, 95
	case score >= 7.0:
		return LevelHigh, 75
	case score >= 4.0:
		return LevelMedium, 50
	case score > 0:
		return LevelLow, 25
	default:
		return LevelInfo, 10
	}
}

// FromLabel normalizes NVD / vendor severity strings.
func FromLabel(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return LevelCritical
	case "high":
		return LevelHigh
	case "medium", "moderate":
		return LevelMedium
	case "low":
		return LevelLow
	default:
		return LevelInfo
	}
}

// NormalizedScore returns a 0–100 prioritization score from level.
func NormalizedScore(level string) int {
	switch level {
	case LevelCritical:
		return 95
	case LevelHigh:
		return 75
	case LevelMedium:
		return 50
	case LevelLow:
		return 25
	default:
		return 10
	}
}
