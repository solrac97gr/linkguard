// Package types contains shared type definitions for linkguard.
package types

// RiskLevel represents the threat level of a analyzed link.
type RiskLevel int

const (
	// RiskNone indicates no suspicious signals detected.
	RiskNone RiskLevel = iota
	// RiskLow indicates minor suspicious signals.
	RiskLow
	// RiskMedium indicates moderate suspicious signals.
	RiskMedium
	// RiskHigh indicates strong suspicious signals.
	RiskHigh
	// RiskCritical indicates very strong suspicious signals.
	RiskCritical
)

// String returns a human-readable representation of the risk level.
func (r RiskLevel) String() string {
	switch r {
	case RiskNone:
		return "none"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Result holds the full analysis output for a URL.
type Result struct {
	// URL is the original input URL.
	URL string

	// Score is the overall suspicion score from 0.0 (safe) to 1.0 (malicious).
	Score float64

	// Risk is the categorical risk level derived from the score.
	Risk RiskLevel

	// Reasons lists human-readable explanations for each detected signal.
	Reasons []string

	// Entropy is the Shannon entropy of the URL string.
	Entropy float64

	// UnicodeFlags contains details about suspicious Unicode usage.
	UnicodeFlags UnicodeReport

	// StructureFlags contains details about suspicious URL structure.
	StructureFlags StructureReport
}

// IsSuspicious returns true if the risk level is Medium or above.
func (r *Result) IsSuspicious() bool {
	return r.Risk >= RiskMedium
}

// UnicodeReport details suspicious Unicode usage in the URL.
type UnicodeReport struct {
	// MixedScripts is true if the URL mixes multiple Unicode scripts (e.g. Latin + Cyrillic).
	MixedScripts bool

	// HomoglyphCount is the number of characters that look like ASCII but are from other scripts.
	HomoglyphCount int

	// InvisibleCharCount is the number of zero-width or invisible Unicode characters.
	InvisibleCharCount int

	// NonASCIIRatio is the fraction of characters that are non-ASCII (0.0 to 1.0).
	NonASCIIRatio float64

	// ScriptsFound lists the Unicode script names found in the URL.
	ScriptsFound []string
}

// StructureReport details suspicious URL structural patterns.
type StructureReport struct {
	// ExcessiveSubdomains is true if the URL has an unusual number of subdomains.
	ExcessiveSubdomains bool

	// SubdomainCount is the number of subdomains (e.g. a.b.c.example.com = 3).
	SubdomainCount int

	// HasIPAddress is true if the host is an IP address instead of a domain.
	HasIPAddress bool

	// HasPortNumber is true if the URL specifies a non-standard port.
	HasPortNumber bool

	// ExcessivePathDepth is true if the path has an unusually deep hierarchy.
	ExcessivePathDepth bool

	// PathDepth is the number of path segments.
	PathDepth int

	// EncodedCharRatio is the fraction of characters that are percent-encoded.
	EncodedCharRatio float64

	// HasDoubleEncoding is true if percent-encoding is applied multiple times.
	HasDoubleEncoding bool

	// SuspiciousTLD is true if the TLD is commonly associated with abuse.
	SuspiciousTLD bool

	// HasAtSign is true if the URL contains an '@' in the authority (user-info trick).
	HasAtSign bool

	// ExcessiveLength is true if the URL length is unusually long.
	ExcessiveLength bool

	// Length is the total character count of the URL.
	Length int
}

// AnalysisMethod defines the interface that all analysis methods must implement.
// Users can create custom analysis methods by implementing this interface.
type AnalysisMethod interface {
	// Analyze performs the analysis on the given URL and populates relevant fields in the result.
	// It returns a suspicion score between 0.0 (safe) and 1.0 (highly suspicious).
	Analyze(rawURL string, result *Result) float64

	// Weight returns the weight (importance) of this analysis method in the final score.
	// Weights don't need to sum to 1.0 - they will be normalized automatically.
	Weight() float64

	// Name returns a human-readable name for this analysis method.
	Name() string
}
