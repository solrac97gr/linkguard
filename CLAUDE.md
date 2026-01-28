# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LinkGuard is a Go library for entropy-based detection of suspicious URLs. It analyzes links across multiple dimensions to identify phishing attempts, homoglyph attacks, obfuscation techniques, and other malicious patterns.

## Core Architecture

The library uses a flexible, extensible analyzer architecture that supports custom analysis methods and configurable weights.

### Analyzer System

The library is built around the `Analyzer` type and `AnalysisMethod` interface:

- **Analyzer**: Manages a collection of analysis methods and coordinates their execution
- **AnalysisMethod Interface**: Defines the contract for all analysis methods (built-in or custom)
- **Built-in Methods**: EntropyAnalysis, UnicodeAnalysis, StructureAnalysis

Users can:
1. Use the default analyzer via `Analyze()` (backward compatible)
2. Create custom analyzers with `NewAnalyzer(methods...)`
3. Implement custom analysis methods by implementing `AnalysisMethod`
4. Adjust weights to prioritize different detection strategies

### Analysis Modules

The library includes three built-in analysis modules that can be used together or independently:

1. **Entropy Analysis** (`entropy.go`): Calculates Shannon entropy to detect randomness/obfuscation
   - Normal URLs: ~3.0-4.5 entropy
   - Suspicious URLs: >4.5 entropy

2. **Unicode Analysis** (`unicode.go`): Detects Unicode-based attacks
   - Homoglyphs: Characters from non-Latin scripts that visually resemble ASCII (e.g., Cyrillic 'а' vs Latin 'a')
   - Invisible characters: Zero-width spaces, joiners, and other hidden Unicode
   - Mixed scripts: Unusual combinations of writing systems

3. **Structure Analysis** (`structure.go`): Examines URL construction patterns
   - IP addresses instead of domains
   - Non-standard ports
   - Excessive subdomains (>3)
   - Path depth (>5 segments)
   - Double encoding (%2520)
   - Suspicious TLDs (.tk, .ml, .ga, etc.)
   - @ sign in authority section
   - Excessive length (>200 chars)

### Scoring System

The main analyzer (`analyzer.go`) combines scores using weighted averages:
- Entropy: 35%
- Unicode: 35%
- Structure: 30%

Final scores map to risk levels:
- 0.0-0.15: None
- 0.15-0.30: Low
- 0.30-0.55: Medium
- 0.55-0.80: High
- 0.80-1.0: Critical

URLs with Medium risk or above are considered suspicious (`Result.IsSuspicious()`).

## Development Commands

### Testing
```bash
# Run all tests
go test

# Run tests with verbose output
go test -v

# Run tests with coverage
go test -cover

# Run specific test
go test -run TestAnalyze_HomoglyphDomain

# Run with race detection
go test -race
```

### Build
```bash
# Build (library doesn't produce binary, but verifies build)
go build

# Verify module dependencies
go mod verify

# Tidy dependencies
go mod tidy
```

### Benchmarks
```bash
# Run all benchmarks
go test -bench=.

# Run benchmarks with memory statistics
go test -bench=. -benchmem

# Run specific benchmark
go test -bench=BenchmarkAnalyze_Simple

# Run benchmarks for longer duration (more accurate)
go test -bench=. -benchtime=5s
```

## Key Functions

- `NewAnalyzer(methods ...AnalysisMethod) *Analyzer`: Create analyzer with specified methods
- `DefaultMethods() []AnalysisMethod`: Get default analysis methods (entropy, unicode, structure)
- `(*Analyzer) Analyze(rawURL string) Result`: Analyze single URL
- `(*Analyzer) AnalyzeMultiple(urls []string) []Result`: Batch analysis
- `ShannonEntropy(s string) float64`: Calculate Shannon entropy
- `NormalizedEntropy(s string) float64`: Entropy normalized to [0,1]

## Test Structure

Tests in `linkguard_test.go` are organized by module:
- Entropy tests: `TestShannonEntropy_*`
- Unicode tests: `TestAnalyzeUnicode_*`
- Structure tests: `TestAnalyzeStructure_*`
- Integration tests: `TestAnalyze_*`

Each analysis function has both unit tests (testing individual components) and integration tests (testing full `Analyze()` flow).

## Important Constants

When modifying thresholds, be aware of these constants in `structure.go`:
- `maxNormalSubdomains = 3`
- `maxNormalPathDepth = 5`
- `maxNormalLength = 200`

Entropy thresholds are in the `entropyScore()` function in `entropy.go`.

## Adding New Detection Patterns

### Option 1: Extend Existing Analysis Methods

To add new patterns to existing methods:

1. Add detection logic to the appropriate analysis function (`analyzeUnicode`, `analyzeStructure`, etc.)
2. Add the flag to the corresponding report struct in `linkguard.go`
3. Update the scoring function (`unicodeScore`, `structureScore`, etc.) to weight the new signal
4. Add human-readable reason in `buildReasons()` in `analyzer.go`
5. Add test cases in `linkguard_test.go`

### Option 2: Create Custom Analysis Methods (Recommended for New Features)

Create a new type implementing `AnalysisMethod`:

```go
type MyCustomAnalysis struct {
    WeightValue float64
    // Custom configuration fields
}

func (m *MyCustomAnalysis) Analyze(rawURL string, result *Result) float64 {
    // Your detection logic
    // Return score 0.0 (safe) to 1.0 (suspicious)
}

func (m *MyCustomAnalysis) Weight() float64 {
    return m.WeightValue
}

func (m *MyCustomAnalysis) Name() string {
    return "My Custom Analysis"
}
```

Then use it:
```go
analyzer := linkguard.NewAnalyzer(
    &linkguard.EntropyAnalysis{WeightValue: 0.3},
    &linkguard.UnicodeAnalysis{WeightValue: 0.3},
    &MyCustomAnalysis{WeightValue: 0.4},
)
```

See the "Custom Analyzers" section in `README.md` for comprehensive examples and `analyzer_test.go` for reference implementations.
