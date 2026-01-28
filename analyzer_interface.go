package linkguard

import (
	"github.com/solrac97gr/linkguard/shannon"
	"github.com/solrac97gr/linkguard/structure"
	"github.com/solrac97gr/linkguard/types"
	"github.com/solrac97gr/linkguard/unicode"
)

// AnalysisMethod is an alias for types.AnalysisMethod for convenience.
type AnalysisMethod = types.AnalysisMethod

// Analyzer performs URL analysis using configured analysis methods.
type Analyzer struct {
	methods []AnalysisMethod
}

// NewAnalyzer creates a new analyzer with analysis methods.
//
// If no methods are provided, returns an analyzer with default methods:
// - Entropy Analysis: 35%
// - Unicode Analysis: 35%
// - Structure Analysis: 30%
//
// Examples:
//
//	// Default configuration
//	analyzer := linkguard.NewAnalyzer()
//
//	// Custom configuration
//	analyzer := linkguard.NewAnalyzer(
//	    shannon.New(0.2),
//	    unicode.New(0.6),
//	    structure.New(0.2),
//	)
func NewAnalyzer(methods ...AnalysisMethod) *Analyzer {
	// If no methods provided, use defaults
	if len(methods) == 0 {
		methods = defaultMethods()
	}

	return &Analyzer{
		methods: methods,
	}
}

// defaultMethods returns the default analysis methods with standard weights.
func defaultMethods() []AnalysisMethod {
	return []AnalysisMethod{
		shannon.New(weightEntropy),
		unicode.New(weightUnicode),
		structure.New(weightStructure),
	}
}

// DefaultMethods returns a copy of the default analysis methods.
// This is useful for advanced use cases where you want to modify or selectively use
// the built-in methods.
//
// For most use cases, simply use NewAnalyzer() with no arguments:
//
//	analyzer := linkguard.NewAnalyzer()  // Recommended
//
// Advanced usage:
//
//	methods := linkguard.DefaultMethods()
//	analyzer := linkguard.NewAnalyzer(methods[0], methods[1])  // Only entropy and unicode
func DefaultMethods() []AnalysisMethod {
	return defaultMethods()
}

// Analyze performs a full analysis of the given URL using all configured analysis methods.
// It returns a Result with the overall risk score, risk level, and detailed reports.
func (a *Analyzer) Analyze(rawURL string) Result {
	result := Result{
		URL: rawURL,
	}

	if len(a.methods) == 0 {
		return result
	}

	totalWeight := 0.0
	totalScore := 0.0

	// Run all analysis methods and collect weighted scores
	for _, method := range a.methods {
		score := method.Analyze(rawURL, &result)
		weight := method.Weight()
		totalScore += score * weight
		totalWeight += weight
	}

	// Normalize the final score
	if totalWeight > 0 {
		result.Score = totalScore / totalWeight
	}

	// Clamp to [0, 1]
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	// Derive risk level
	result.Risk = riskFromScore(result.Score)

	// Build human-readable reasons
	result.Reasons = buildReasons(result)

	return result
}

// AnalyzeMultiple analyzes multiple URLs using this analyzer.
func (a *Analyzer) AnalyzeMultiple(urls []string) []Result {
	results := make([]Result, len(urls))
	for i, u := range urls {
		results[i] = a.Analyze(u)
	}
	return results
}

// AddMethod adds a new analysis method to this analyzer.
// This modifies the analyzer in-place.
func (a *Analyzer) AddMethod(method AnalysisMethod) {
	a.methods = append(a.methods, method)
}

// Methods returns a copy of the analysis methods used by this analyzer.
func (a *Analyzer) Methods() []AnalysisMethod {
	methods := make([]AnalysisMethod, len(a.methods))
	copy(methods, a.methods)
	return methods
}
