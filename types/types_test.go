package types_test

import (
	"testing"

	"github.com/solrac97gr/linkguard/types"
)

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		name     string
		risk     types.RiskLevel
		expected string
	}{
		{"None", types.RiskNone, "none"},
		{"Low", types.RiskLow, "low"},
		{"Medium", types.RiskMedium, "medium"},
		{"High", types.RiskHigh, "high"},
		{"Critical", types.RiskCritical, "critical"},
		{"Unknown", types.RiskLevel(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.risk.String(); got != tt.expected {
				t.Errorf("RiskLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestResult_IsSuspicious(t *testing.T) {
	tests := []struct {
		name     string
		risk     types.RiskLevel
		expected bool
	}{
		{"None is not suspicious", types.RiskNone, false},
		{"Low is not suspicious", types.RiskLow, false},
		{"Medium is suspicious", types.RiskMedium, true},
		{"High is suspicious", types.RiskHigh, true},
		{"Critical is suspicious", types.RiskCritical, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &types.Result{Risk: tt.risk}
			if got := result.IsSuspicious(); got != tt.expected {
				t.Errorf("Result.IsSuspicious() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestResult_Fields(t *testing.T) {
	result := types.Result{
		URL:   "https://example.com",
		Score: 0.5,
		Risk:  types.RiskMedium,
		Reasons: []string{
			"high entropy",
			"homoglyph detected",
		},
		Entropy: 4.6,
		UnicodeFlags: types.UnicodeReport{
			MixedScripts:       true,
			HomoglyphCount:     2,
			InvisibleCharCount: 1,
			NonASCIIRatio:      0.15,
			ScriptsFound:       []string{"ASCII", "Cyrillic"},
		},
		StructureFlags: types.StructureReport{
			ExcessiveSubdomains: true,
			SubdomainCount:      4,
			HasIPAddress:        false,
			HasPortNumber:       true,
			ExcessivePathDepth:  false,
			PathDepth:           3,
			EncodedCharRatio:    0.1,
			HasDoubleEncoding:   false,
			SuspiciousTLD:       false,
			HasAtSign:           false,
			ExcessiveLength:     false,
			Length:              150,
		},
	}

	if result.URL != "https://example.com" {
		t.Errorf("URL = %v, want https://example.com", result.URL)
	}
	if result.Score != 0.5 {
		t.Errorf("Score = %v, want 0.5", result.Score)
	}
	if result.Risk != types.RiskMedium {
		t.Errorf("Risk = %v, want RiskMedium", result.Risk)
	}
	if len(result.Reasons) != 2 {
		t.Errorf("len(Reasons) = %v, want 2", len(result.Reasons))
	}
	if result.Entropy != 4.6 {
		t.Errorf("Entropy = %v, want 4.6", result.Entropy)
	}
	if result.UnicodeFlags.HomoglyphCount != 2 {
		t.Errorf("UnicodeFlags.HomoglyphCount = %v, want 2", result.UnicodeFlags.HomoglyphCount)
	}
	if result.StructureFlags.SubdomainCount != 4 {
		t.Errorf("StructureFlags.SubdomainCount = %v, want 4", result.StructureFlags.SubdomainCount)
	}
}

func TestUnicodeReport_Fields(t *testing.T) {
	report := types.UnicodeReport{
		MixedScripts:       true,
		HomoglyphCount:     3,
		InvisibleCharCount: 2,
		NonASCIIRatio:      0.25,
		ScriptsFound:       []string{"ASCII", "Greek", "Cyrillic"},
	}

	if !report.MixedScripts {
		t.Error("MixedScripts should be true")
	}
	if report.HomoglyphCount != 3 {
		t.Errorf("HomoglyphCount = %v, want 3", report.HomoglyphCount)
	}
	if report.InvisibleCharCount != 2 {
		t.Errorf("InvisibleCharCount = %v, want 2", report.InvisibleCharCount)
	}
	if report.NonASCIIRatio != 0.25 {
		t.Errorf("NonASCIIRatio = %v, want 0.25", report.NonASCIIRatio)
	}
	if len(report.ScriptsFound) != 3 {
		t.Errorf("len(ScriptsFound) = %v, want 3", len(report.ScriptsFound))
	}
}

func TestStructureReport_Fields(t *testing.T) {
	report := types.StructureReport{
		ExcessiveSubdomains: true,
		SubdomainCount:      5,
		HasIPAddress:        true,
		HasPortNumber:       true,
		ExcessivePathDepth:  true,
		PathDepth:           8,
		EncodedCharRatio:    0.3,
		HasDoubleEncoding:   true,
		SuspiciousTLD:       true,
		HasAtSign:           true,
		ExcessiveLength:     true,
		Length:              250,
	}

	if !report.ExcessiveSubdomains {
		t.Error("ExcessiveSubdomains should be true")
	}
	if report.SubdomainCount != 5 {
		t.Errorf("SubdomainCount = %v, want 5", report.SubdomainCount)
	}
	if !report.HasIPAddress {
		t.Error("HasIPAddress should be true")
	}
	if !report.HasPortNumber {
		t.Error("HasPortNumber should be true")
	}
	if !report.ExcessivePathDepth {
		t.Error("ExcessivePathDepth should be true")
	}
	if report.PathDepth != 8 {
		t.Errorf("PathDepth = %v, want 8", report.PathDepth)
	}
	if report.EncodedCharRatio != 0.3 {
		t.Errorf("EncodedCharRatio = %v, want 0.3", report.EncodedCharRatio)
	}
	if !report.HasDoubleEncoding {
		t.Error("HasDoubleEncoding should be true")
	}
	if !report.SuspiciousTLD {
		t.Error("SuspiciousTLD should be true")
	}
	if !report.HasAtSign {
		t.Error("HasAtSign should be true")
	}
	if !report.ExcessiveLength {
		t.Error("ExcessiveLength should be true")
	}
	if report.Length != 250 {
		t.Errorf("Length = %v, want 250", report.Length)
	}
}
