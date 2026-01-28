package linkguard_test

import (
	"reflect"
	"testing"

	"github.com/solrac97gr/linkguard"
	"github.com/solrac97gr/linkguard/shannon"
	"github.com/solrac97gr/linkguard/types"
	"github.com/solrac97gr/linkguard/unicode"
)

// Mock analysis method for testing custom analyzers
type mockAnalysis struct {
	name        string
	weightValue float64
	scoreValue  float64
}

func (m *mockAnalysis) Analyze(rawURL string, result *types.Result) float64 {
	// For testing, we can set a mock flag
	if m.name == "MockSuspicious" {
		result.Reasons = append(result.Reasons, "mock suspicious reason")
	}
	return m.scoreValue
}

func (m *mockAnalysis) Weight() float64 {
	return m.weightValue
}

func (m *mockAnalysis) Name() string {
	return m.name
}

func TestNewAnalyzer_Default(t *testing.T) {
	analyzer := linkguard.NewAnalyzer()
	methods := analyzer.Methods()

	if len(methods) != 3 {
		t.Fatalf("Expected 3 default methods, got %d", len(methods))
	}

	expectedNames := []string{"Entropy Analysis", "Unicode Analysis", "Structure Analysis"}
	for i, method := range methods {
		if method.Name() != expectedNames[i] {
			t.Errorf("Expected method %d to be %s, got %s", i, expectedNames[i], method.Name())
		}
	}
}

func TestNewAnalyzer_Custom(t *testing.T) {
	customMethods := []types.AnalysisMethod{
		shannon.New(0.5),
		unicode.New(0.5),
	}
	analyzer := linkguard.NewAnalyzer(customMethods...)
	methods := analyzer.Methods()

	if len(methods) != 2 {
		t.Fatalf("Expected 2 custom methods, got %d", len(methods))
	}
	if methods[0].Name() != "Entropy Analysis" || methods[1].Name() != "Unicode Analysis" {
		t.Error("Custom methods not set correctly")
	}
}

func TestAnalyzer_Analyze_Simple(t *testing.T) {
	analyzer := linkguard.NewAnalyzer()
	result := analyzer.Analyze("https://example.com")

	if result.Risk != types.RiskNone {
		t.Errorf("Expected RiskNone for clean URL, got %s", result.Risk)
	}
	if result.Score > 0.1 {
		t.Errorf("Expected low score for clean URL, got %f", result.Score)
	}
	if !reflect.DeepEqual(result.URL, "https://example.com") {
		t.Errorf("Expected URL to be 'https://example.com', got %s", result.URL)
	}
}

func TestAnalyzer_Analyze_Suspicious(t *testing.T) {
	analyzer := linkguard.NewAnalyzer()
	// URL with homoglyphs, high entropy, and suspicious TLD
	url := "https://раураl.tk/ab_cde-fgh123?q=randomstring"
	result := analyzer.Analyze(url)

	if !result.IsSuspicious() {
		t.Error("Expected URL to be suspicious")
	}
	if result.Risk < types.RiskMedium {
		t.Errorf("Expected at least RiskMedium, got %s", result.Risk)
	}
	if len(result.Reasons) == 0 {
		t.Error("Expected reasons for suspicious URL")
	}
}

func TestDefaultMethods(t *testing.T) {
	methods := linkguard.DefaultMethods()
	if len(methods) != 3 {
		t.Errorf("Expected 3 default methods, got %d", len(methods))
	}
}

func TestAddMethod(t *testing.T) {
	analyzer := linkguard.NewAnalyzer()
	initialCount := len(analyzer.Methods())

	analyzer.AddMethod(&mockAnalysis{name: "Test", weightValue: 0.1, scoreValue: 0.5})
	newCount := len(analyzer.Methods())

	if newCount != initialCount+1 {
		t.Errorf("Expected method count to be %d, got %d", initialCount+1, newCount)
	}
}

func TestRiskFromScore(t *testing.T) {
	// This is testing an internal function, which is not ideal, but good for coverage.
	// Access via a public wrapper if this test is considered inappropriate.
	tests := []struct {
		score    float64
		expected types.RiskLevel
	}{
		{0.1, types.RiskNone},
		{0.2, types.RiskLow},
		{0.4, types.RiskMedium},
		{0.7, types.RiskHigh},
		{0.9, types.RiskCritical},
	}

	// Since riskFromScore is not exported, we test it via the public Analyze method.
	for _, tt := range tests {
		analyzer := linkguard.NewAnalyzer(&mockAnalysis{
			name:        "Mock",
			weightValue: 1.0,
			scoreValue:  tt.score,
		})
		result := analyzer.Analyze("http://mock.url")
		if result.Risk != tt.expected {
			t.Errorf("For score %f, expected risk %s, got %s", tt.score, tt.expected, result.Risk)
		}
	}
}

func TestBuildReasons(t *testing.T) {
	// Also testing an internal function via a public method.
	result := types.Result{
		Entropy: 5.0,
		UnicodeFlags: types.UnicodeReport{
			MixedScripts:   true,
			HomoglyphCount: 1,
			ScriptsFound:   []string{"ASCII", "Cyrillic"},
		},
		StructureFlags: types.StructureReport{
			HasIPAddress: true,
		},
	}

	analyzer := linkguard.NewAnalyzer() // Use a real analyzer to trigger buildReasons
	// Manually construct a result to test reason generation
	result.Reasons = analyzer.Analyze("http://1.2.3.4/раураl").Reasons

	if len(result.Reasons) < 3 {
		t.Errorf("Expected at least 3 reasons, got %d", len(result.Reasons))
	}
}

func BenchmarkAnalyze(b *testing.B) {
	analyzer := linkguard.NewAnalyzer()
	url := "https://www.google.com/search?q=golang+benchmarks"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(url)
	}
}

func BenchmarkAnalyze_Suspicious(b *testing.B) {
	analyzer := linkguard.NewAnalyzer()
	url := "https://microsоft.com/login/auth?next=http%3A%2F%2Fevil.tk"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(url)
	}
}
