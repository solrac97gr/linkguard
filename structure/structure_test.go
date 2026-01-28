package structure_test

import (
	"testing"

	"github.com/solrac97gr/linkguard/structure"
	"github.com/solrac97gr/linkguard/types"
)

func TestAnalyze_CleanURL(t *testing.T) {
	url := "https://example.com/path"
	report := structure.Analyze(url)

	if report.HasIPAddress {
		t.Error("HasIPAddress should be false")
	}
	if report.HasPortNumber {
		t.Error("HasPortNumber should be false")
	}
	if report.ExcessiveSubdomains {
		t.Error("ExcessiveSubdomains should be false")
	}
	if report.ExcessivePathDepth {
		t.Error("ExcessivePathDepth should be false")
	}
	if report.HasDoubleEncoding {
		t.Error("HasDoubleEncoding should be false")
	}
	if report.SuspiciousTLD {
		t.Error("SuspiciousTLD should be false")
	}
	if report.HasAtSign {
		t.Error("HasAtSign should be false")
	}
	if report.ExcessiveLength {
		t.Error("ExcessiveLength should be false")
	}
}

func TestAnalyze_IPAddress(t *testing.T) {
	url := "http://192.168.1.1/login"
	report := structure.Analyze(url)
	if !report.HasIPAddress {
		t.Error("HasIPAddress should be true for IP-based URL")
	}
}

func TestAnalyze_PortNumber(t *testing.T) {
	url := "https://example.com:8080"
	report := structure.Analyze(url)
	if !report.HasPortNumber {
		t.Error("HasPortNumber should be true for non-standard port")
	}
}

func TestAnalyze_ExcessiveSubdomains(t *testing.T) {
	url := "https://a.b.c.d.e.f.example.com"
	report := structure.Analyze(url)
	if !report.ExcessiveSubdomains {
		t.Error("ExcessiveSubdomains should be true")
	}
	if report.SubdomainCount <= 3 {
		t.Errorf("SubdomainCount = %d, want > 3", report.SubdomainCount)
	}
}

func TestAnalyze_ExcessivePathDepth(t *testing.T) {
	url := "https://example.com/a/b/c/d/e/f/g"
	report := structure.Analyze(url)
	if !report.ExcessivePathDepth {
		t.Error("ExcessivePathDepth should be true")
	}
	if report.PathDepth <= 5 {
		t.Errorf("PathDepth = %d, want > 5", report.PathDepth)
	}
}

func TestAnalyze_Encoding(t *testing.T) {
	tests := []struct {
		name            string
		url             string
		expectDouble    bool
		minEncodedRatio float64
	}{
		{
			name:            "double encoding",
			url:             "https://example.com/path%2520here",
			expectDouble:    true,
			minEncodedRatio: 0.0,
		},
		{
			name:            "high encoding ratio",
			url:             "https://example.com/%20%21%22%23%24%25%26%27%28%29%2A",
			expectDouble:    true,
			minEncodedRatio: 0.2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := structure.Analyze(tt.url)
			if report.HasDoubleEncoding != tt.expectDouble {
				t.Errorf("HasDoubleEncoding = %v, want %v", report.HasDoubleEncoding, tt.expectDouble)
			}
			if report.EncodedCharRatio < tt.minEncodedRatio {
				t.Errorf("EncodedCharRatio = %f, want >= %f", report.EncodedCharRatio, tt.minEncodedRatio)
			}
		})
	}
}

func TestAnalyze_SuspiciousTLD(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		expect bool
	}{
		{"known suspicious .tk", "http://example.tk", true},
		{"known suspicious .xyz", "http://example.xyz", true},
		{"normal .com", "http://example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := structure.Analyze(tt.url)
			if report.SuspiciousTLD != tt.expect {
				t.Errorf("SuspiciousTLD = %v, want %v for %s", report.SuspiciousTLD, tt.expect, tt.url)
			}
		})
	}
}

func TestAnalyze_AtSign(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		expect bool
	}{
		{"@ in authority", "https://user@example.com", true},
		{"@ in path", "https://example.com/path@info", false},
		{"no @", "https://example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := structure.Analyze(tt.url)
			if report.HasAtSign != tt.expect {
				t.Errorf("HasAtSign = %v, want %v for %s", report.HasAtSign, tt.expect, tt.url)
			}
		})
	}
}

func TestAnalyze_ExcessiveLength(t *testing.T) {
	var longURL = "https://example.com/" + string(make([]byte, 250))
	report := structure.Analyze(longURL)
	if !report.ExcessiveLength {
		t.Error("ExcessiveLength should be true for very long URL")
	}
	if report.Length < 200 {
		t.Errorf("Length = %d, want > 200", report.Length)
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name     string
		report   types.StructureReport
		minScore float64
	}{
		{"clean", types.StructureReport{}, 0.0},
		{"ip address", types.StructureReport{HasIPAddress: true}, 0.3},
		{"port number", types.StructureReport{HasPortNumber: true}, 0.15},
		{"excessive subdomains", types.StructureReport{ExcessiveSubdomains: true}, 0.2},
		{"excessive path", types.StructureReport{ExcessivePathDepth: true}, 0.1},
		{"double encoding", types.StructureReport{HasDoubleEncoding: true}, 0.3},
		{"high encoding ratio", types.StructureReport{EncodedCharRatio: 0.3}, 0.3},
		{"suspicious tld", types.StructureReport{SuspiciousTLD: true}, 0.2},
		{"at sign", types.StructureReport{HasAtSign: true}, 0.35},
		{"excessive length", types.StructureReport{ExcessiveLength: true}, 0.1},
		{"multiple flags", types.StructureReport{HasIPAddress: true, HasAtSign: true, SuspiciousTLD: true}, 0.85},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := structure.Score(tt.report)
			if score < tt.minScore {
				t.Errorf("Score() = %f, want >= %f", score, tt.minScore)
			}
			if score > 1.0 {
				t.Errorf("Score() = %f, should not be > 1.0", score)
			}
		})
	}
}

func TestNew(t *testing.T) {
	analyzer := structure.New(0.3)
	if analyzer.Weight() != 0.3 {
		t.Errorf("Weight() = %f, want 0.3", analyzer.Weight())
	}
	if analyzer.Name() != "Structure Analysis" {
		t.Errorf("Name() = %s, want 'Structure Analysis'", analyzer.Name())
	}
}

func TestAnalysis_Analyze(t *testing.T) {
	analyzer := structure.New(0.3)
	result := &types.Result{}
	score := analyzer.Analyze("http://1.2.3.4/path", result)

	if score <= 0.0 {
		t.Error("Analyze score should be > 0 for suspicious URL")
	}
	if !result.StructureFlags.HasIPAddress {
		t.Error("StructureFlags.HasIPAddress should have been set")
	}
}
