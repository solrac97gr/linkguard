package unicode_test

import (
	"testing"

	"github.com/solrac97gr/linkguard/types"
	"github.com/solrac97gr/linkguard/unicode"
)

func TestAnalyze_Clean(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"simple domain", "https://example.com"},
		{"with path", "https://example.com/path/to/page"},
		{"with query", "https://example.com?param=value"},
		{"with subdomain", "https://www.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := unicode.Analyze(tt.url)

			if report.HomoglyphCount != 0 {
				t.Errorf("HomoglyphCount = %v, want 0", report.HomoglyphCount)
			}
			if report.InvisibleCharCount != 0 {
				t.Errorf("InvisibleCharCount = %v, want 0", report.InvisibleCharCount)
			}
			if report.MixedScripts {
				t.Errorf("MixedScripts should be false for clean ASCII URL, got %v for %s", report.MixedScripts, tt.url)
			}
			if report.NonASCIIRatio != 0.0 {
				t.Errorf("NonASCIIRatio = %v, want 0.0", report.NonASCIIRatio)
			}
		})
	}
}

func TestAnalyze_Homoglyphs(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedCount int
	}{
		{
			name:          "Cyrillic A",
			url:           "https://exАmple.com", // Cyrillic А
			expectedCount: 1,
		},
		{
			name:          "Cyrillic O",
			url:           "https://gООgle.com", // Two Cyrillic О
			expectedCount: 2,
		},
		{
			name:          "Greek O",
			url:           "https://gΟΟgle.com", // Two Greek Ο
			expectedCount: 2,
		},
		{
			name:          "Mixed homoglyphs",
			url:           "https://ехаmple.com", // Cyrillic е, х, а
			expectedCount: 3,
		},
		{
			name:          "Fullwidth Latin",
			url:           "https://ＡＢＣ.com", // Fullwidth A, B, C
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := unicode.Analyze(tt.url)

			if report.HomoglyphCount != tt.expectedCount {
				t.Errorf("HomoglyphCount = %v, want %v", report.HomoglyphCount, tt.expectedCount)
			}
			if !report.MixedScripts {
				t.Errorf("MixedScripts should be true when homoglyphs are present, got %v for %s", report.MixedScripts, tt.url)
			}
		})
	}
}

func TestAnalyze_InvisibleChars(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedCount int
	}{
		{
			name:          "zero-width space",
			url:           "https://exam\u200Bple.com",
			expectedCount: 1,
		},
		{
			name:          "zero-width non-joiner",
			url:           "https://exam\u200Cple.com",
			expectedCount: 1,
		},
		{
			name:          "zero-width joiner",
			url:           "https://exam\u200Dple.com",
			expectedCount: 1,
		},
		{
			name:          "multiple invisible",
			url:           "https://ex\u200Bam\u200Cple\u200D.com",
			expectedCount: 3,
		},
		{
			name:          "soft hyphen",
			url:           "https://exam\u00ADple.com",
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := unicode.Analyze(tt.url)

			if report.InvisibleCharCount != tt.expectedCount {
				t.Errorf("InvisibleCharCount = %v, want %v", report.InvisibleCharCount, tt.expectedCount)
			}
		})
	}
}

func TestAnalyze_MixedScripts(t *testing.T) {
	tests := []struct {
		name            string
		url             string
		expectMixed     bool
		expectedScripts []string
	}{
		{
			name:            "ASCII only",
			url:             "https://example.com",
			expectMixed:     false,
			expectedScripts: []string{"ASCII"},
		},
		{
			name:            "Latin only",
			url:             "https://café.com",
			expectMixed:     false,
			expectedScripts: []string{"ASCII", "Latin"},
		},
		{
			name:            "Cyrillic mixed",
			url:             "https://exampleА.com",
			expectMixed:     true,
			expectedScripts: []string{"ASCII", "Cyrillic"},
		},
		{
			name:            "Greek mixed",
			url:             "https://exampleΑ.com",
			expectMixed:     true,
			expectedScripts: []string{"ASCII", "Greek"},
		},
		{
			name:            "Multiple non-Latin",
			url:             "https://АΑ.com",
			expectMixed:     true,
			expectedScripts: []string{"ASCII", "Cyrillic", "Greek"},
		},
		{
			name:        "Fullwidth Latin",
			url:         "https://ＡＢＣ.com",
			expectMixed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := unicode.Analyze(tt.url)

			if report.MixedScripts != tt.expectMixed {
				t.Errorf("MixedScripts = %v, want %v for %s", report.MixedScripts, tt.expectMixed, tt.url)
			}

			if len(tt.expectedScripts) > 0 {
				if len(report.ScriptsFound) != len(tt.expectedScripts) {
					t.Errorf("len(ScriptsFound) = %v, want %v. Got: %v, Want: %v",
						len(report.ScriptsFound), len(tt.expectedScripts), report.ScriptsFound, tt.expectedScripts)
				}
			}
		})
	}
}

func TestAnalyze_NonASCIIRatio(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expectedRatio float64
		delta         float64
	}{
		{
			name:          "all ASCII",
			url:           "https://example.com",
			expectedRatio: 0.0,
			delta:         0.01,
		},
		{
			name:          "some non-ASCII",
			url:           "café",
			expectedRatio: 0.25, // 1 out of 4
			delta:         0.01,
		},
		{
			name:          "all non-ASCII",
			url:           "ΑΒΓΔ",
			expectedRatio: 1.0,
			delta:         0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := unicode.Analyze(tt.url)

			diff := report.NonASCIIRatio - tt.expectedRatio
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.delta {
				t.Errorf("NonASCIIRatio = %v, want %v (±%v)", report.NonASCIIRatio, tt.expectedRatio, tt.delta)
			}
		})
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name     string
		report   types.UnicodeReport
		minScore float64
		maxScore float64
	}{
		{
			name: "clean URL",
			report: types.UnicodeReport{
				MixedScripts:       false,
				HomoglyphCount:     0,
				InvisibleCharCount: 0,
				NonASCIIRatio:      0.0,
			},
			minScore: 0.0,
			maxScore: 0.0,
		},
		{
			name: "mixed scripts only",
			report: types.UnicodeReport{
				MixedScripts:       true,
				HomoglyphCount:     0,
				InvisibleCharCount: 0,
				NonASCIIRatio:      0.05,
			},
			minScore: 0.3,
			maxScore: 0.5,
		},
		{
			name: "one homoglyph",
			report: types.UnicodeReport{
				MixedScripts:       true,
				HomoglyphCount:     1,
				InvisibleCharCount: 0,
				NonASCIIRatio:      0.05,
			},
			minScore: 0.6,
			maxScore: 0.8,
		},
		{
			name: "multiple homoglyphs",
			report: types.UnicodeReport{
				MixedScripts:       true,
				HomoglyphCount:     5,
				InvisibleCharCount: 0,
				NonASCIIRatio:      0.2,
			},
			minScore: 0.9,
			maxScore: 1.0,
		},
		{
			name: "invisible characters",
			report: types.UnicodeReport{
				MixedScripts:       false,
				HomoglyphCount:     0,
				InvisibleCharCount: 3,
				NonASCIIRatio:      0.1,
			},
			minScore: 0.5,
			maxScore: 0.7,
		},
		{
			name: "high non-ASCII ratio",
			report: types.UnicodeReport{
				MixedScripts:       false,
				HomoglyphCount:     0,
				InvisibleCharCount: 0,
				NonASCIIRatio:      0.5,
			},
			minScore: 0.1,
			maxScore: 0.3,
		},
		{
			name: "multiple indicators",
			report: types.UnicodeReport{
				MixedScripts:       true,
				HomoglyphCount:     3,
				InvisibleCharCount: 2,
				NonASCIIRatio:      0.4,
			},
			minScore: 1.0,
			maxScore: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := unicode.Score(tt.report)

			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("Score() = %v, want between %v and %v", score, tt.minScore, tt.maxScore)
			}

			if score < 0.0 || score > 1.0 {
				t.Errorf("Score() = %v, must be between 0.0 and 1.0", score)
			}
		})
	}
}

func TestNew(t *testing.T) {
	weight := 0.35
	analyzer := unicode.New(weight)

	if analyzer == nil {
		t.Fatal("New() returned nil")
	}

	if analyzer.Weight() != weight {
		t.Errorf("Weight() = %v, want %v", analyzer.Weight(), weight)
	}

	if analyzer.Name() != "Unicode Analysis" {
		t.Errorf("Name() = %v, want 'Unicode Analysis'", analyzer.Name())
	}
}

func TestAnalysis_Analyze(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		weight      float64
		expectScore bool
	}{
		{
			name:        "clean URL",
			url:         "https://example.com",
			weight:      0.35,
			expectScore: true,
		},
		{
			name:        "suspicious URL",
			url:         "https://exАmple.com", // Cyrillic А
			weight:      0.35,
			expectScore: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := unicode.New(tt.weight)
			result := &types.Result{}

			score := analyzer.Analyze(tt.url, result)

			if tt.expectScore && (score < 0.0 || score > 1.0) {
				t.Errorf("Analyze() score = %v, want between 0.0 and 1.0", score)
			}
		})
	}
}

// Benchmark tests
func BenchmarkAnalyze(b *testing.B) {
	url := "https://example.com/path/to/resource"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		unicode.Analyze(url)
	}
}

func BenchmarkAnalyze_WithHomoglyphs(b *testing.B) {
	url := "https://exАmple.com/pаth/tо/resоurce" // Contains Cyrillic homoglyphs
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		unicode.Analyze(url)
	}
}

func BenchmarkScore(b *testing.B) {
	report := types.UnicodeReport{
		MixedScripts:       true,
		HomoglyphCount:     3,
		InvisibleCharCount: 1,
		NonASCIIRatio:      0.2,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		unicode.Score(report)
	}
}
