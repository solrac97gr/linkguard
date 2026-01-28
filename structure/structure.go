// Package structure provides URL structure pattern analysis.
package structure

import (
	"net"
	"net/url"
	"strings"

	"github.com/solrac97gr/linkguard/types"
)

// analysis performs structural pattern analysis on URLs.
type analysis struct {
	weightValue float64
}

// New creates a new structure analyzer with the specified weight.
//
// The weight determines the importance of structure analysis in the final score.
// Standard weight is 0.30 (30%).
//
// Example:
//
//	analyzer := linkguard.NewAnalyzer(
//	    shannon.New(0.35),
//	    unicode.New(0.35),
//	    structure.New(0.30),
//	)
func New(weight float64) types.AnalysisMethod {
	return &analysis{weightValue: weight}
}

// Analyze implements the AnalysisMethod interface for structure analysis.
func (a *analysis) Analyze(rawURL string, result *types.Result) float64 {
	result.StructureFlags = Analyze(rawURL)
	return Score(result.StructureFlags)
}

// Weight returns the weight of structure analysis.
func (a *analysis) Weight() float64 {
	return a.weightValue
}

// Name returns the name of this analysis method.
func (a *analysis) Name() string {
	return "Structure Analysis"
}

// Suspicious TLDs commonly associated with abuse or free registration.
var suspiciousTLDs = map[string]bool{
	".tk":       true,
	".ml":       true,
	".ga":       true,
	".cf":       true,
	".gq":       true,
	".buzz":     true,
	".top":      true,
	".work":     true,
	".click":    true,
	".link":     true,
	".info":     true,
	".xyz":      true,
	".rest":     true,
	".fit":      true,
	".loan":     true,
	".racing":   true,
	".win":      true,
	".review":   true,
	".country":  true,
	".stream":   true,
	".download": true,
	".gdn":      true,
	".mom":      true,
	".party":    true,
	".science":  true,
	".date":     true,
	".faith":    true,
	".zip":      true,
	".mov":      true,
}

const (
	maxNormalSubdomains = 3
	maxNormalPathDepth  = 5
	maxNormalLength     = 200
)

// Analyze inspects the URL structure for suspicious patterns.
func Analyze(rawURL string) types.StructureReport {
	report := types.StructureReport{
		Length: len(rawURL),
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		// Unparseable URL is itself suspicious; return what we can.
		report.ExcessiveLength = len(rawURL) > maxNormalLength
		return report
	}

	host := parsed.Hostname()
	port := parsed.Port()

	// Check for IP address as host.
	if ip := net.ParseIP(host); ip != nil {
		report.HasIPAddress = true
	}

	// Check for non-standard port.
	if port != "" && port != "80" && port != "443" {
		report.HasPortNumber = true
	}

	// Count subdomains.
	if !report.HasIPAddress && host != "" {
		parts := strings.Split(host, ".")
		if len(parts) > 2 {
			report.SubdomainCount = len(parts) - 2
		}
		report.ExcessiveSubdomains = report.SubdomainCount > maxNormalSubdomains
	}

	// Check path depth.
	path := strings.Trim(parsed.Path, "/")
	if path != "" {
		segments := strings.Split(path, "/")
		report.PathDepth = len(segments)
	}
	report.ExcessivePathDepth = report.PathDepth > maxNormalPathDepth

	// Check percent-encoding ratio.
	encodedCount := strings.Count(rawURL, "%")
	if len(rawURL) > 0 {
		report.EncodedCharRatio = float64(encodedCount) / float64(len(rawURL))
	}

	// Check for double encoding (e.g., %2520 = double-encoded space).
	report.HasDoubleEncoding = strings.Contains(rawURL, "%25")

	// Check for suspicious TLD.
	if host != "" {
		dotIdx := strings.LastIndex(host, ".")
		if dotIdx >= 0 {
			tld := strings.ToLower(host[dotIdx:])
			report.SuspiciousTLD = suspiciousTLDs[tld]
		}
	}

	// Check for @ sign in authority (credential-stuffing / phishing trick).
	report.HasAtSign = strings.Contains(parsed.User.String(), "") && parsed.User != nil ||
		strings.Contains(rawURL, "@")

	// Clean up: only flag @ if it appears before the host portion.
	if report.HasAtSign {
		schemeEnd := strings.Index(rawURL, "://")
		if schemeEnd >= 0 {
			authority := rawURL[schemeEnd+3:]
			slashIdx := strings.Index(authority, "/")
			if slashIdx >= 0 {
				authority = authority[:slashIdx]
			}
			report.HasAtSign = strings.Contains(authority, "@")
		}
	}

	report.ExcessiveLength = len(rawURL) > maxNormalLength

	return report
}

// Score converts the structure report into a 0.0-1.0 suspicion score.
func Score(r types.StructureReport) float64 {
	score := 0.0

	if r.HasIPAddress {
		score += 0.3
	}

	if r.HasPortNumber {
		score += 0.15
	}

	if r.ExcessiveSubdomains {
		score += 0.2
	}

	if r.ExcessivePathDepth {
		score += 0.1
	}

	if r.HasDoubleEncoding {
		score += 0.3
	}

	if r.EncodedCharRatio > 0.2 {
		score += 0.3
	} else if r.EncodedCharRatio > 0.1 {
		score += 0.15
	}

	if r.SuspiciousTLD {
		score += 0.2
	}

	if r.HasAtSign {
		score += 0.35
	}

	if r.ExcessiveLength {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}
