package shannon_test

import (
	"math"
	"testing"

	"github.com/solrac97gr/linkguard/shannon"
	"github.com/solrac97gr/linkguard/types"
)

func TestCalculate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
		delta    float64
	}{
		{
			name:     "empty string",
			input:    "",
			expected: 0.0,
			delta:    0.01,
		},
		{
			name:     "single character",
			input:    "a",
			expected: 0.0,
			delta:    0.01,
		},
		{
			name:     "repeated character",
			input:    "aaaa",
			expected: 0.0,
			delta:    0.01,
		},
		{
			name:     "simple URL",
			input:    "https://example.com",
			expected: 3.0,
			delta:    1.0, // Wide range as we're testing it's in normal range
		},
		{
			name:     "random string",
			input:    "xK9mP2vQ8jR",
			expected: 3.46, // High entropy
			delta:    0.5,
		},
		{
			name:     "binary string",
			input:    "01010101",
			expected: 1.0,
			delta:    0.01,
		},
		{
			name:     "uniform distribution",
			input:    "abcdefghij",
			expected: 3.32, // log2(10)
			delta:    0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannon.Calculate(tt.input)
			if math.Abs(got-tt.expected) > tt.delta {
				t.Errorf("Calculate(%q) = %v, want %v (±%v)", tt.input, got, tt.expected, tt.delta)
			}
		})
	}
}

func TestNormalized(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		minVal float64
		maxVal float64
	}{
		{
			name:   "empty string",
			input:  "",
			minVal: 0.0,
			maxVal: 0.0,
		},
		{
			name:   "single character",
			input:  "a",
			minVal: 0.0,
			maxVal: 0.0,
		},
		{
			name:   "repeated character",
			input:  "aaaa",
			minVal: 0.0,
			maxVal: 0.0,
		},
		{
			name:   "two different characters",
			input:  "ab",
			minVal: 0.0,
			maxVal: 1.0,
		},
		{
			name:   "uniform distribution should be close to 1",
			input:  "abcdefghij",
			minVal: 0.9,
			maxVal: 1.0,
		},
		{
			name:   "normal URL",
			input:  "https://example.com",
			minVal: 0.0,
			maxVal: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannon.Normalized(tt.input)
			if got < tt.minVal || got > tt.maxVal {
				t.Errorf("Normalized(%q) = %v, want between %v and %v", tt.input, got, tt.minVal, tt.maxVal)
			}
		})
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name     string
		entropy  float64
		expected float64
	}{
		{"very low entropy", 2.0, 0.0},
		{"low entropy", 3.5, 0.0},
		{"slightly elevated", 3.7, 0.1},
		{"moderate entropy", 4.2, 0.3},
		{"suspicious entropy", 4.7, 0.6},
		{"high entropy", 5.2, 0.8},
		{"very high entropy", 6.0, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannon.Score(tt.entropy)
			if got != tt.expected {
				t.Errorf("Score(%v) = %v, want %v", tt.entropy, got, tt.expected)
			}
		})
	}
}

func TestNew(t *testing.T) {
	weight := 0.5
	analyzer := shannon.New(weight)

	if analyzer == nil {
		t.Fatal("New() returned nil")
	}

	if analyzer.Weight() != weight {
		t.Errorf("Weight() = %v, want %v", analyzer.Weight(), weight)
	}

	if analyzer.Name() != "Entropy Analysis" {
		t.Errorf("Name() = %v, want 'Entropy Analysis'", analyzer.Name())
	}
}

func TestAnalysis_Analyze(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		weight        float64
		expectScore   bool
		expectEntropy bool
	}{
		{
			name:          "normal URL",
			url:           "https://example.com",
			weight:        0.35,
			expectScore:   true,
			expectEntropy: true,
		},
		{
			name:          "suspicious URL",
			url:           "https://xK9mP2vQ8jR.tk/aB3dEf7gH",
			weight:        0.35,
			expectScore:   true,
			expectEntropy: true,
		},
		{
			name:          "empty URL",
			url:           "",
			weight:        0.35,
			expectScore:   true,
			expectEntropy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := shannon.New(tt.weight)
			result := &types.Result{}

			score := analyzer.Analyze(tt.url, result)

			if tt.expectScore && score < 0.0 || score > 1.0 {
				t.Errorf("Analyze() score = %v, want between 0.0 and 1.0", score)
			}

			if tt.expectEntropy && result.Entropy == 0.0 && tt.url != "" {
				t.Error("Analyze() did not set Entropy in result")
			}
		})
	}
}

func TestAnalysis_Weight(t *testing.T) {
	weights := []float64{0.1, 0.35, 0.5, 1.0}

	for _, weight := range weights {
		t.Run("weight", func(t *testing.T) {
			analyzer := shannon.New(weight)
			if analyzer.Weight() != weight {
				t.Errorf("Weight() = %v, want %v", analyzer.Weight(), weight)
			}
		})
	}
}

// Benchmark tests
func BenchmarkCalculate(b *testing.B) {
	url := "https://example.com/path/to/resource?param=value"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shannon.Calculate(url)
	}
}

func BenchmarkNormalized(b *testing.B) {
	url := "https://example.com/path/to/resource?param=value"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shannon.Normalized(url)
	}
}

func BenchmarkScore(b *testing.B) {
	entropy := 4.5
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shannon.Score(entropy)
	}
}

func BenchmarkAnalyze(b *testing.B) {
	analyzer := shannon.New(0.35)
	url := "https://example.com/path/to/resource?param=value"
	result := &types.Result{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(url, result)
	}
}
