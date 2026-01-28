// Package linkguard provides entropy-based detection of suspicious links.
//
// Links used for phishing or obfuscation often contain unusual Unicode characters,
// homoglyphs, excessive encoding, or high Shannon entropy. This library analyzes
// URLs across multiple dimensions and produces a threat score.
//
// Usage:
//
//	result := linkguard.Analyze("https://example.com")
//	if result.IsSuspicious() {
//	    fmt.Println("Suspicious link detected:", result.Reasons)
//	}
package linkguard

import "github.com/solrac97gr/linkguard/types"

// Re-export types for backward compatibility and convenience.
type (
	Result          = types.Result
	RiskLevel       = types.RiskLevel
	UnicodeReport   = types.UnicodeReport
	StructureReport = types.StructureReport
)

// Re-export risk level constants.
const (
	RiskNone     = types.RiskNone
	RiskLow      = types.RiskLow
	RiskMedium   = types.RiskMedium
	RiskHigh     = types.RiskHigh
	RiskCritical = types.RiskCritical
)
