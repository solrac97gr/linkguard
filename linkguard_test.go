package linkguard

import (
	"math"
	"testing"
)

// --- Entropy tests ---

func TestShannonEntropy_Empty(t *testing.T) {
	if e := ShannonEntropy(""); e != 0 {
		t.Errorf("expected 0 for empty string, got %f", e)
	}
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	if e := ShannonEntropy("aaaa"); e != 0 {
		t.Errorf("expected 0 for uniform string, got %f", e)
	}
}

func TestShannonEntropy_MaxBinary(t *testing.T) {
	// "ab" repeated = 50/50 distribution = 1.0 bit entropy
	e := ShannonEntropy("ab")
	if math.Abs(e-1.0) > 0.001 {
		t.Errorf("expected ~1.0 for 'ab', got %f", e)
	}
}

func TestShannonEntropy_URL(t *testing.T) {
	e := ShannonEntropy("https://www.google.com")
	if e < 3.0 || e > 4.5 {
		t.Errorf("expected normal URL entropy 3.0-4.5, got %f", e)
	}
}

func TestNormalizedEntropy(t *testing.T) {
	n := NormalizedEntropy("ab")
	if math.Abs(n-1.0) > 0.001 {
		t.Errorf("expected 1.0 normalized entropy for 'ab', got %f", n)
	}

	n2 := NormalizedEntropy("")
	if n2 != 0 {
		t.Errorf("expected 0 for empty, got %f", n2)
	}
}

// --- Unicode tests ---

func TestAnalyzeUnicode_Clean(t *testing.T) {
	report := analyzeUnicode("https://www.example.com/path?q=test")
	if report.MixedScripts {
		t.Error("expected no mixed scripts for clean ASCII URL")
	}
	if report.HomoglyphCount != 0 {
		t.Errorf("expected 0 homoglyphs, got %d", report.HomoglyphCount)
	}
	if report.InvisibleCharCount != 0 {
		t.Errorf("expected 0 invisible chars, got %d", report.InvisibleCharCount)
	}
}

func TestAnalyzeUnicode_Homoglyphs(t *testing.T) {
	// Mix Cyrillic 'а' (U+0430) into what looks like "example"
	report := analyzeUnicode("https://ex\u0430mple.com")
	if report.HomoglyphCount < 1 {
		t.Error("expected at least 1 homoglyph")
	}
	if !report.MixedScripts {
		t.Error("expected mixed scripts detection")
	}
}

func TestAnalyzeUnicode_InvisibleChars(t *testing.T) {
	// Insert zero-width space
	report := analyzeUnicode("https://example\u200B.com")
	if report.InvisibleCharCount < 1 {
		t.Error("expected at least 1 invisible character")
	}
}

func TestAnalyzeUnicode_FullwidthChars(t *testing.T) {
	// Fullwidth 'Ａ' (U+FF21)
	report := analyzeUnicode("https://\uFF21\uFF42c.com")
	if report.HomoglyphCount < 2 {
		t.Errorf("expected at least 2 fullwidth homoglyphs, got %d", report.HomoglyphCount)
	}
}

// --- Structure tests ---

func TestAnalyzeStructure_Clean(t *testing.T) {
	report := analyzeStructure("https://www.example.com/page")
	if report.HasIPAddress {
		t.Error("should not detect IP address")
	}
	if report.HasPortNumber {
		t.Error("should not detect non-standard port")
	}
	if report.HasAtSign {
		t.Error("should not detect @ sign")
	}
	if report.SuspiciousTLD {
		t.Error("should not flag .com as suspicious")
	}
}

func TestAnalyzeStructure_IPAddress(t *testing.T) {
	report := analyzeStructure("http://192.168.1.1/admin")
	if !report.HasIPAddress {
		t.Error("should detect IP address")
	}
}

func TestAnalyzeStructure_NonStandardPort(t *testing.T) {
	report := analyzeStructure("https://example.com:8443/api")
	if !report.HasPortNumber {
		t.Error("should detect non-standard port")
	}
}

func TestAnalyzeStructure_StandardPort(t *testing.T) {
	report := analyzeStructure("https://example.com:443/api")
	if report.HasPortNumber {
		t.Error("port 443 should not be flagged")
	}
}

func TestAnalyzeStructure_ExcessiveSubdomains(t *testing.T) {
	report := analyzeStructure("https://a.b.c.d.e.example.com/page")
	if !report.ExcessiveSubdomains {
		t.Errorf("expected excessive subdomains, count=%d", report.SubdomainCount)
	}
}

func TestAnalyzeStructure_DoubleEncoding(t *testing.T) {
	report := analyzeStructure("https://example.com/%2520admin")
	if !report.HasDoubleEncoding {
		t.Error("should detect double encoding")
	}
}

func TestAnalyzeStructure_SuspiciousTLD(t *testing.T) {
	report := analyzeStructure("https://login-bank.tk/secure")
	if !report.SuspiciousTLD {
		t.Error("should flag .tk as suspicious TLD")
	}
}

func TestAnalyzeStructure_AtSign(t *testing.T) {
	report := analyzeStructure("https://google.com@evil.com/login")
	if !report.HasAtSign {
		t.Error("should detect @ sign in authority")
	}
}

func TestAnalyzeStructure_ExcessiveLength(t *testing.T) {
	long := "https://example.com/" + string(make([]byte, 250))
	report := analyzeStructure(long)
	if !report.ExcessiveLength {
		t.Error("should detect excessive length")
	}
}

// --- Full Analyze integration tests ---

func TestAnalyze_SafeURL(t *testing.T) {
	result := Analyze("https://www.google.com")
	if result.IsSuspicious() {
		t.Errorf("google.com should not be suspicious, score=%.2f, reasons=%v", result.Score, result.Reasons)
	}
	if result.Risk > RiskLow {
		t.Errorf("expected RiskNone or RiskLow, got %s", result.Risk)
	}
}

func TestAnalyze_HomoglyphDomain(t *testing.T) {
	// "gооgle.com" with Cyrillic 'о' (U+043E) instead of Latin 'o'
	result := Analyze("https://g\u043E\u043Egle.com")
	if !result.IsSuspicious() {
		t.Errorf("homoglyph domain should be suspicious, score=%.2f", result.Score)
	}
	if len(result.Reasons) == 0 {
		t.Error("expected at least one reason")
	}
}

func TestAnalyze_IPWithPort(t *testing.T) {
	result := Analyze("http://192.168.1.1:8080/admin/login")
	if result.StructureFlags.HasIPAddress != true {
		t.Error("should detect IP")
	}
	if result.StructureFlags.HasPortNumber != true {
		t.Error("should detect port")
	}
}

func TestAnalyze_HighEntropyRandom(t *testing.T) {
	// Highly random URL
	result := Analyze("https://x7k9q2m4.tk/a8f3e1b5c7d9?x=j2k4l6m8n0p1q3r5")
	if result.Entropy < 4.0 {
		t.Errorf("expected high entropy, got %.2f", result.Entropy)
	}
}

func TestAnalyze_InvisibleChars(t *testing.T) {
	result := Analyze("https://exam\u200Bple\u200C.com\u200D/login")
	if result.UnicodeFlags.InvisibleCharCount < 3 {
		t.Errorf("expected 3 invisible chars, got %d", result.UnicodeFlags.InvisibleCharCount)
	}
	if !result.IsSuspicious() {
		t.Error("URL with invisible characters should be suspicious")
	}
}

func TestAnalyze_PhishingAtSign(t *testing.T) {
	result := Analyze("https://accounts.google.com@evil-site.tk/login")
	if !result.StructureFlags.HasAtSign {
		t.Error("should detect @ sign")
	}
	if !result.StructureFlags.SuspiciousTLD {
		t.Error("should detect suspicious TLD")
	}
}

func TestAnalyzeMultiple(t *testing.T) {
	urls := []string{
		"https://www.google.com",
		"https://g\u043E\u043Egle.com",
	}
	results := AnalyzeMultiple(urls)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Score >= results[1].Score {
		t.Error("homoglyph URL should score higher than clean URL")
	}
}

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		level RiskLevel
		want  string
	}{
		{RiskNone, "none"},
		{RiskLow, "low"},
		{RiskMedium, "medium"},
		{RiskHigh, "high"},
		{RiskCritical, "critical"},
		{RiskLevel(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("RiskLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}
