# 🛡️ LinkGuard

[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.24-blue.svg)](https://golang.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/solrac97gr/linkguard)](https://goreportcard.com/report/github.com/solrac97gr/linkguard)

A high-performance Go library for detecting suspicious and potentially malicious URLs through entropy-based analysis, Unicode inspection, and structural pattern recognition.

## 🎯 Features

LinkGuard provides multi-dimensional URL analysis to detect:

- **🔢 Entropy Analysis**: Detects randomized/obfuscated URLs using Shannon entropy calculations
- **🌍 Unicode Attacks**: Identifies homoglyphs (look-alike characters), invisible characters, and mixed scripts
- **🏗️ Structural Anomalies**: Recognizes suspicious patterns like IP addresses, excessive subdomains, double encoding, and suspicious TLDs
- **📊 Risk Scoring**: Provides both numeric scores (0.0-1.0) and categorical risk levels (None, Low, Medium, High, Critical)
- **💬 Human-Readable Reports**: Generates detailed explanations for each detected suspicious signal
- **⚡ High Performance**: Sub-microsecond analysis for simple URLs, ~3µs for complex URLs
- **🔧 Customizable**: Create custom analyzers with selected methods or implement your own analysis logic
- **🎨 Flexible Architecture**: Mix and match built-in methods, adjust weights, or add custom detection algorithms

## 📦 Installation

```bash
go get github.com/solrac97gr/linkguard
```

## 🚀 Quick Start

```go
package main

import (
    "fmt"
    "github.com/solrac97gr/linkguard"
)

func main() {
    // Create analyzer (uses default configuration)
    analyzer := linkguard.NewAnalyzer()

    // Analyze a single URL
    result := analyzer.Analyze("https://g\u043E\u043Egle.com/login")

    if result.IsSuspicious() {
        fmt.Printf("⚠️  Suspicious link detected!\n")
        fmt.Printf("Risk Level: %s\n", result.Risk)
        fmt.Printf("Score: %.2f\n", result.Score)
        fmt.Printf("Reasons:\n")
        for _, reason := range result.Reasons {
            fmt.Printf("  - %s\n", reason)
        }
    } else {
        fmt.Printf("✅ URL appears safe (Risk: %s)\n", result.Risk)
    }
}
```

**Output:**
```
⚠️  Suspicious link detected!
Risk Level: medium
Score: 0.53
Reasons:
  - mixed Unicode scripts detected: [ASCII Cyrillic]
  - 2 homoglyph character(s) found (look-alike characters from other scripts)
```

## 📚 Usage Examples

### Basic URL Analysis

```go
// Create analyzer (uses default configuration)
analyzer := linkguard.NewAnalyzer()

// Analyze a normal URL
result := analyzer.Analyze("https://www.example.com")
fmt.Printf("Score: %.2f, Risk: %s\n", result.Score, result.Risk)
// Output: Score: 0.03, Risk: none
```

### Batch Analysis

```go
// Create analyzer
analyzer := linkguard.NewAnalyzer()

urls := []string{
    "https://www.google.com",
    "https://g\u043E\u043Egle.com",  // Homoglyph attack
    "http://192.168.1.1:8080/admin",
    "https://example.tk/phishing",
}

results := analyzer.AnalyzeMultiple(urls)
for i, result := range results {
    fmt.Printf("URL %d: %s (%.2f)\n", i+1, result.Risk, result.Score)
}
```

### Detailed Inspection

```go
analyzer := linkguard.NewAnalyzer()
result := analyzer.Analyze("https://subdomain.example.com/path")

// Access entropy information
fmt.Printf("Shannon Entropy: %.2f\n", result.Entropy)

// Access Unicode analysis
fmt.Printf("Homoglyphs detected: %d\n", result.UnicodeFlags.HomoglyphCount)
fmt.Printf("Scripts found: %v\n", result.UnicodeFlags.ScriptsFound)

// Access structural analysis
fmt.Printf("Has IP address: %t\n", result.StructureFlags.HasIPAddress)
fmt.Printf("Subdomain count: %d\n", result.StructureFlags.SubdomainCount)
fmt.Printf("Path depth: %d\n", result.StructureFlags.PathDepth)
```

### Custom Entropy Analysis

```go
// Calculate Shannon entropy independently
url := "https://x7k9q2m4.tk/a8f3e1b5c7d9"
entropy := linkguard.ShannonEntropy(url)
fmt.Printf("Entropy: %.2f\n", entropy)

// Get normalized entropy (0.0-1.0)
normalized := linkguard.NormalizedEntropy(url)
fmt.Printf("Normalized: %.2f\n", normalized)
```

## 🔧 Custom Analyzers

LinkGuard provides a flexible architecture that allows you to customize detection logic.

### Creating Analyzers

All analyzers are created using `NewAnalyzer()`:

```go
// Default configuration (Entropy: 35%, Unicode: 35%, Structure: 30%)
analyzer := linkguard.NewAnalyzer()
result := analyzer.Analyze("https://example.com")
```

### Using Subpackages for Custom Configuration

Import analysis method packages and configure weights explicitly:

```go
import (
    "github.com/solrac97gr/linkguard"
    "github.com/solrac97gr/linkguard/shannon"
    "github.com/solrac97gr/linkguard/unicode"
    "github.com/solrac97gr/linkguard/structure"
)

// Custom analyzer with specific weights
analyzer := linkguard.NewAnalyzer(
    shannon.New(0.2),    // 20% entropy
    unicode.New(0.6),    // 60% unicode
    structure.New(0.2),  // 20% structure
)

// Use only specific analysis methods
analyzer := linkguard.NewAnalyzer(
    unicode.New(1.0),    // Only unicode detection
)
```

### Customizing Weights for Different Use Cases

Adjust the importance of different analysis methods based on your security focus:

```go
import (
    "github.com/solrac97gr/linkguard"
    "github.com/solrac97gr/linkguard/shannon"
    "github.com/solrac97gr/linkguard/unicode"
    "github.com/solrac97gr/linkguard/structure"
)

// Security-focused: prioritize structure over entropy
securityAnalyzer := linkguard.NewAnalyzer(
    shannon.New(0.2),
    unicode.New(0.3),
    structure.New(0.5),
)

// Phishing-focused: prioritize Unicode detection
phishingAnalyzer := linkguard.NewAnalyzer(
    shannon.New(0.2),
    unicode.New(0.6),
    structure.New(0.2),
)

// Obfuscation-focused: prioritize entropy
obfuscationAnalyzer := linkguard.NewAnalyzer(
    shannon.New(0.7),
    unicode.New(0.2),
    structure.New(0.1),
)
```

### Creating Custom Analysis Methods

Implement the `AnalysisMethod` interface to create your own detection logic:

```go
type AnalysisMethod interface {
    Analyze(rawURL string, result *Result) float64  // Returns 0.0-1.0 score
    Weight() float64                                 // Returns method weight
    Name() string                                    // Returns method name
}
```

#### Example 1: Keyword-Based Analysis

```go
type KeywordAnalysis struct {
    WeightValue float64
    Keywords    []string
}

func (k *KeywordAnalysis) Analyze(rawURL string, result *linkguard.Result) float64 {
    if k.Keywords == nil {
        k.Keywords = []string{"login", "admin", "password", "verify"}
    }

    lowercaseURL := strings.ToLower(rawURL)
    for _, keyword := range k.Keywords {
        if strings.Contains(lowercaseURL, keyword) {
            return 0.8  // High suspicion score for keyword match
        }
    }
    return 0.0
}

func (k *KeywordAnalysis) Weight() float64 {
    if k.WeightValue == 0 {
        return 0.3  // default weight
    }
    return k.WeightValue
}

func (k *KeywordAnalysis) Name() string {
    return "Keyword Analysis"
}

// Usage
analyzer := linkguard.NewAnalyzer(
    &linkguard.EntropyAnalysis{WeightValue: 0.3},
    &linkguard.UnicodeAnalysis{WeightValue: 0.3},
    &KeywordAnalysis{
        WeightValue: 0.4,
        Keywords:    []string{"login", "verify", "secure", "banking"},
    },
)
```

#### Example 2: Length-Based Analysis

```go
type LengthAnalysis struct {
    WeightValue float64
    MaxLength   int
}

func (l *LengthAnalysis) Analyze(rawURL string, result *linkguard.Result) float64 {
    maxLen := l.MaxLength
    if maxLen == 0 {
        maxLen = 100  // default threshold
    }

    if len(rawURL) > maxLen {
        excess := float64(len(rawURL) - maxLen)
        score := excess / 100.0
        if score > 1.0 {
            return 1.0
        }
        return score
    }
    return 0.0
}

func (l *LengthAnalysis) Weight() float64 {
    if l.WeightValue == 0 {
        return 0.2
    }
    return l.WeightValue
}

func (l *LengthAnalysis) Name() string {
    return "Length Analysis"
}
```

#### Example 3: TLD Whitelist Analysis

```go
type TLDWhitelistAnalysis struct {
    WeightValue    float64
    AllowedTLDs    map[string]bool
    PenaltyScore   float64
}

func (t *TLDWhitelistAnalysis) Analyze(rawURL string, result *linkguard.Result) float64 {
    if t.AllowedTLDs == nil {
        t.AllowedTLDs = map[string]bool{
            ".com": true,
            ".org": true,
            ".edu": true,
            ".gov": true,
        }
    }

    parsed, err := url.Parse(rawURL)
    if err != nil {
        return 0.5  // parsing failure is suspicious
    }

    host := parsed.Hostname()
    for tld := range t.AllowedTLDs {
        if strings.HasSuffix(host, tld) {
            return 0.0  // whitelisted TLD
        }
    }

    // Non-whitelisted TLD
    if t.PenaltyScore == 0 {
        return 0.4
    }
    return t.PenaltyScore
}

func (t *TLDWhitelistAnalysis) Weight() float64 {
    if t.WeightValue == 0 {
        return 0.25
    }
    return t.WeightValue
}

func (t *TLDWhitelistAnalysis) Name() string {
    return "TLD Whitelist Analysis"
}
```

### Specialized Analyzers for Common Use Cases

#### Email Link Scanner

Designed to detect phishing links in emails:

```go
import (
    "github.com/solrac97gr/linkguard"
    "github.com/solrac97gr/linkguard/unicode"
    "github.com/solrac97gr/linkguard/structure"
)

func NewEmailLinkAnalyzer() *linkguard.Analyzer {
    return linkguard.NewAnalyzer(
        unicode.New(0.4),     // Homoglyph attacks common in phishing
        structure.New(0.3),   // IP addresses, suspicious TLDs
        &KeywordAnalysis{
            WeightValue: 0.3,
            Keywords:    []string{"verify", "urgent", "suspended", "confirm", "account"},
        },
    )
}

// Usage
emailAnalyzer := NewEmailLinkAnalyzer()
results := emailAnalyzer.AnalyzeMultiple(extractedLinks)
```

#### Suspicious Redirect Detector

Designed to detect malicious redirects:

```go
import (
    "github.com/solrac97gr/linkguard"
    "github.com/solrac97gr/linkguard/shannon"
    "github.com/solrac97gr/linkguard/structure"
)

func NewRedirectAnalyzer() *linkguard.Analyzer {
    return linkguard.NewAnalyzer(
        shannon.New(0.3),
        structure.New(0.4),
        &LengthAnalysis{
            WeightValue: 0.3,
            MaxLength:   150,  // Long URLs often used in malicious redirects
        },
    )
}
```

#### Internal Application Validator

For validating URLs within controlled environments:

```go
import (
    "github.com/solrac97gr/linkguard"
    "github.com/solrac97gr/linkguard/structure"
)

func NewInternalURLValidator(allowedDomains []string) *linkguard.Analyzer {
    domainMap := make(map[string]bool)
    for _, d := range allowedDomains {
        domainMap[d] = true
    }

    return linkguard.NewAnalyzer(
        structure.New(0.5),
        &TLDWhitelistAnalysis{
            WeightValue: 0.5,
            AllowedTLDs: map[string]bool{".com": true, ".org": true},
        },
    )
}
```

### Dynamic Method Addition

Add analysis methods to an analyzer after creation:

```go
import (
    "github.com/solrac97gr/linkguard"
    "github.com/solrac97gr/linkguard/shannon"
)

analyzer := linkguard.NewAnalyzer(shannon.New(0.5))

// Add more methods at runtime
analyzer.AddMethod(&KeywordAnalysis{
    WeightValue: 0.5,
    Keywords:    []string{"phishing", "suspicious"},
})

result := analyzer.Analyze(url)
```

### Inspecting Analyzer Configuration

```go
analyzer := linkguard.NewAnalyzer()

methods := analyzer.Methods()
for _, method := range methods {
    fmt.Printf("Method: %s, Weight: %.2f\n", method.Name(), method.Weight())
}
// Output:
// Method: Entropy Analysis, Weight: 0.35
// Method: Unicode Analysis, Weight: 0.35
// Method: Structure Analysis, Weight: 0.30
```

### Best Practices

1. **Weight Normalization**: Weights don't need to sum to 1.0 - they're automatically normalized
2. **Zero Weights**: If `WeightValue` is 0 or negative, the method will use its default weight
3. **Stateless Methods**: Keep analysis methods stateless when possible for thread safety
4. **Error Handling**: Return a moderate score (0.4-0.6) when errors occur during analysis
5. **Testing**: Always test custom methods with both safe and suspicious URLs
6. **Performance**: For batch operations, create the analyzer once and reuse it

### Thread Safety

The `Analyzer` and analysis methods are safe for concurrent use:

```go
analyzer := linkguard.NewAnalyzer()

var wg sync.WaitGroup
for _, url := range urls {
    wg.Add(1)
    go func(u string) {
        defer wg.Done()
        result := analyzer.Analyze(u)
        // Process result...
    }(url)
}
wg.Wait()
```

## 🔍 Detection Capabilities

### Unicode-Based Attacks

| Attack Type | Example | Detection |
|-------------|---------|-----------|
| Homoglyphs | `g\u043E\u043Egle.com` (Cyrillic о) | ✅ Detected |
| Invisible chars | `exam\u200Bple.com` (zero-width space) | ✅ Detected |
| Mixed scripts | Latin + Cyrillic + Greek | ✅ Detected |
| Fullwidth chars | `\uFF21bc.com` (fullwidth A) | ✅ Detected |

### Structural Patterns

| Pattern | Example | Risk Impact |
|---------|---------|-------------|
| IP address | `http://192.168.1.1/admin` | +0.3 |
| Non-standard port | `https://example.com:8443` | +0.15 |
| Excessive subdomains | `a.b.c.d.e.example.com` | +0.2 |
| Double encoding | `%2520admin` | +0.3 |
| Suspicious TLD | `.tk`, `.ml`, `.ga` | +0.2 |
| @ sign trick | `google.com@evil.com` | +0.35 |
| Excessive length | >200 characters | +0.1 |

### Entropy Ranges

| Entropy | Classification | Example |
|---------|----------------|---------|
| 0.0-3.5 | Normal | `https://example.com` |
| 3.5-4.0 | Slightly elevated | `https://my-site123.com/page` |
| 4.0-4.5 | Mildly suspicious | Short random strings |
| 4.5-5.0 | Suspicious | `https://x7k9q2m4.tk` |
| 5.0+ | Highly suspicious | Long random strings |

## 📊 Performance Benchmarks

Benchmarks run on Apple M3 (arm64):

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| **Single URL Analysis** |
| Simple URL | 1.59 µs | 1.2 KB | 9 |
| Complex URL | 3.32 µs | 1.2 KB | 10 |
| Suspicious URL | 2.93 µs | 1.5 KB | 19 |
| Long URL | 6.64 µs | 2.7 KB | 16 |
| **Batch Analysis** |
| 5 URLs | 18.4 µs | 8.8 KB | 68 |
| 3 URLs | 8.27 µs | 4.5 KB | 39 |
| **Component Benchmarks** |
| Shannon Entropy (simple) | 759 ns | 936 B | 5 |
| Unicode Analysis (ASCII) | 539 ns | 16 B | 1 |
| Structure Analysis | 235 ns | 240 B | 3 |
| **Parallel Performance** |
| Analyze (parallel) | 791 ns | 1.2 KB | 10 |
| Multiple (parallel) | 4.93 µs | 8.8 KB | 68 |

**Key Takeaways:**
- ⚡ **Sub-microsecond** analysis for simple URLs
- 🚀 **~3 µs** for complex URL analysis
- 💾 **Low memory footprint** (~1-3 KB per URL)
- 🔄 **Excellent parallel scaling** for batch operations

Run benchmarks yourself:
```bash
go test -bench=. -benchmem
```

## 🏗️ Architecture

LinkGuard uses a weighted scoring system that combines three independent analysis modules:

```
┌─────────────────────────────────────────┐
│          Analyze(url string)            │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
┌───────────────┐   ┌───────────────┐
│    Entropy    │   │    Unicode    │
│   Analysis    │   │   Analysis    │
│   (35% wt.)   │   │   (35% wt.)   │
└───────┬───────┘   └───────┬───────┘
        │                   │
        └──────────┬────────┘
                   │
                   ▼
         ┌─────────────────┐
         │    Structure    │
         │    Analysis     │
         │   (30% wt.)     │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │  Weighted Sum   │
         │   Score [0,1]   │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │   Risk Level    │
         │  (None → Crit)  │
         └─────────────────┘
```

### Risk Level Mapping

| Score Range | Risk Level |
|-------------|------------|
| 0.00 - 0.15 | None |
| 0.15 - 0.30 | Low |
| 0.30 - 0.55 | Medium (Suspicious) |
| 0.55 - 0.80 | High |
| 0.80 - 1.00 | Critical |

## 📖 API Reference

### Analyzer Creation

#### `NewAnalyzer(methods ...AnalysisMethod) *Analyzer`
Creates an analyzer with specified analysis methods.

When called with no arguments, returns an analyzer with default configuration (Entropy: 35%, Unicode: 35%, Structure: 30%).

**Parameters:** Optional variadic list of `AnalysisMethod` implementations.

**Returns:** Configured `Analyzer` instance.

**Examples:**
```go
// Default configuration
analyzer := linkguard.NewAnalyzer()

// Custom configuration using subpackages
import (
    "github.com/solrac97gr/linkguard"
    "github.com/solrac97gr/linkguard/shannon"
    "github.com/solrac97gr/linkguard/unicode"
)

analyzer := linkguard.NewAnalyzer(
    shannon.New(0.4),
    unicode.New(0.6),
)
```

### Analyzer Methods

#### `(*Analyzer) Analyze(rawURL string) Result`
Analyzes a URL using the analyzer's configured methods.

**Parameters:** URL string to analyze.

**Returns:** `Result` with analysis details.

#### `(*Analyzer) AnalyzeMultiple(urls []string) []Result`
Analyzes multiple URLs using the analyzer's configured methods.

**Parameters:** Slice of URL strings.

**Returns:** Slice of `Result` structs.

#### `(*Analyzer) AddMethod(method AnalysisMethod)`
Adds a new analysis method to the analyzer.

**Parameters:** `AnalysisMethod` implementation to add.

#### `(*Analyzer) Methods() []AnalysisMethod`
Returns a copy of the analysis methods used by the analyzer.

**Returns:** Slice of `AnalysisMethod` interfaces.

### Utility Functions

#### `ShannonEntropy(s string) float64`
Calculates Shannon entropy of a string.

**Returns:** Entropy value (typically 0.0-6.0 for URLs).

#### `NormalizedEntropy(s string) float64`
Calculates Shannon entropy normalized to [0, 1].

**Returns:** Normalized entropy value.

### Built-in Analysis Method Subpackages

#### `shannon.New(weight float64) AnalysisMethod`
Creates a Shannon entropy analyzer.

**Package:** `github.com/solrac97gr/linkguard/shannon`

**Parameters:** `weight` - importance of this method (standard: 0.35)

**Returns:** `AnalysisMethod` for entropy detection

#### `unicode.New(weight float64) AnalysisMethod`
Creates a Unicode attack detector.

**Package:** `github.com/solrac97gr/linkguard/unicode`

**Parameters:** `weight` - importance of this method (standard: 0.35)

**Returns:** `AnalysisMethod` for homoglyph and script detection

#### `structure.New(weight float64) AnalysisMethod`
Creates a URL structure analyzer.

**Package:** `github.com/solrac97gr/linkguard/structure`

**Parameters:** `weight` - importance of this method (standard: 0.30)

**Returns:** `AnalysisMethod` for structural pattern detection

### Custom Analysis Methods Interface

Create custom analysis methods by implementing:

```go
type AnalysisMethod interface {
    Analyze(rawURL string, result *Result) float64  // Returns 0.0-1.0 score
    Weight() float64                                 // Returns method weight
    Name() string                                    // Returns method name
}
```

### Result Structure

```go
type Result struct {
    URL            string          // Original input URL
    Score          float64         // Overall suspicion score (0.0-1.0)
    Risk           RiskLevel       // Categorical risk level
    Reasons        []string        // Human-readable explanations
    Entropy        float64         // Shannon entropy
    UnicodeFlags   UnicodeReport   // Unicode analysis details
    StructureFlags StructureReport // Structure analysis details
}
```

#### `IsSuspicious() bool`
Returns `true` if risk level is Medium or above.

### Risk Levels

```go
const (
    RiskNone     RiskLevel = iota  // No suspicious signals
    RiskLow                        // Minor suspicious signals
    RiskMedium                     // Moderate suspicious signals
    RiskHigh                       // Strong suspicious signals
    RiskCritical                   // Very strong suspicious signals
)
```

### Report Structures

#### `UnicodeReport`
```go
type UnicodeReport struct {
    MixedScripts       bool     // Multiple Unicode scripts detected
    HomoglyphCount     int      // Number of look-alike characters
    InvisibleCharCount int      // Number of invisible/zero-width chars
    NonASCIIRatio      float64  // Fraction of non-ASCII characters
    ScriptsFound       []string // Unicode script names found
}
```

#### `StructureReport`
```go
type StructureReport struct {
    ExcessiveSubdomains bool    // >3 subdomains
    SubdomainCount      int     // Number of subdomains
    HasIPAddress        bool    // Host is IP address
    HasPortNumber       bool    // Non-standard port specified
    ExcessivePathDepth  bool    // >5 path segments
    PathDepth           int     // Number of path segments
    EncodedCharRatio    float64 // Percent-encoded character ratio
    HasDoubleEncoding   bool    // Multiple encoding layers
    SuspiciousTLD       bool    // TLD associated with abuse
    HasAtSign           bool    // @ in authority section
    ExcessiveLength     bool    // >200 characters
    Length              int     // Total character count
}
```

## 🛠️ Development

### Running Tests

```bash
# Run all tests
go test

# Run with coverage
go test -cover

# Run specific test
go test -run TestAnalyze_HomoglyphDomain

# Run with race detection
go test -race -v
```

### Running Benchmarks

```bash
# Run all benchmarks
go test -bench=.

# Run with memory statistics
go test -bench=. -benchmem

# Run specific benchmark
go test -bench=BenchmarkAnalyze_Simple

# Run for longer duration
go test -bench=. -benchtime=5s
```

### Project Structure

```
linkguard/
├── analyzer.go              # Main analysis coordinator and scoring
├── analyzer_interface.go    # Analyzer and AnalysisMethod interfaces
├── methods.go               # Built-in analysis method implementations
├── entropy.go               # Shannon entropy calculations
├── unicode.go               # Unicode and homoglyph detection
├── structure.go             # URL structure analysis
├── linkguard.go             # Public API and type definitions
├── linkguard_test.go        # Unit and integration tests
├── analyzer_test.go         # Analyzer and custom method tests
├── examples_test.go         # Usage examples
├── linkguard_bench_test.go  # Performance benchmarks
├── CLAUDE.md                # AI assistant guidance
└── README.md                # Complete documentation (you are here)
```

## 🎯 Use Cases

- **Email Security**: Scan links in emails before allowing users to click
- **Web Proxies**: Filter suspicious URLs at the gateway level
- **Chat Applications**: Protect users from malicious links in messages
- **Security Tools**: Integrate into SIEM, threat intelligence platforms
- **Browser Extensions**: Real-time link safety checking
- **API Gateways**: Validate redirect URLs and callback endpoints
- **Incident Response**: Analyze URLs from security incidents

## ⚠️ Limitations

- **Not a complete security solution**: Should be used as part of a layered defense strategy
- **False positives possible**: Legitimate URLs with unusual characteristics may be flagged
- **No DNS/WHOIS checking**: Only analyzes the URL string itself
- **No active scanning**: Does not fetch or execute URLs
- **Best effort Unicode detection**: Some advanced Unicode attacks may evade detection

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report bugs**: Open an issue with detailed reproduction steps
2. **Suggest features**: Propose new detection patterns or improvements
3. **Submit PRs**: Add new detection capabilities or fix bugs
4. **Improve docs**: Help make documentation clearer

When contributing:
- Write tests for new features
- Run benchmarks to ensure no performance regression
- Follow existing code style
- Update documentation as needed

## 🙏 Acknowledgments

Built with inspiration from:
- OWASP URL validation guidelines
- Unicode security best practices
- Shannon's information theory
- Phishing detection research

## 📬 Contact

- GitHub: [@solrac97gr](https://github.com/solrac97gr)
- Issues: [GitHub Issues](https://github.com/solrac97gr/linkguard/issues)

---

**Made with ❤️ by Carlos Garcia**
