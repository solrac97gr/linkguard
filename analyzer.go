package linkguard

import "fmt"

// Weight configuration for combining sub-scores.
const (
	weightEntropy   = 0.35
	weightUnicode   = 0.35
	weightStructure = 0.30
)

// Analyze performs a full entropy and structural analysis of the given URL string
// and returns a Result with the overall risk score, risk level, and detailed reports.
func Analyze(rawURL string) Result {
	result := Result{
		URL: rawURL,
	}

	// 1. Shannon entropy analysis.
	result.Entropy = ShannonEntropy(rawURL)
	eScore := entropyScore(result.Entropy)

	// 2. Unicode / homoglyph analysis.
	result.UnicodeFlags = analyzeUnicode(rawURL)
	uScore := unicodeScore(result.UnicodeFlags)

	// 3. Structural analysis.
	result.StructureFlags = analyzeStructure(rawURL)
	sScore := structureScore(result.StructureFlags)

	// Weighted combination.
	result.Score = eScore*weightEntropy + uScore*weightUnicode + sScore*weightStructure

	// Clamp to [0, 1].
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	// Derive risk level.
	result.Risk = riskFromScore(result.Score)

	// Build human-readable reasons.
	result.Reasons = buildReasons(result)

	return result
}

// AnalyzeMultiple analyzes a slice of URLs and returns results for each.
func AnalyzeMultiple(urls []string) []Result {
	results := make([]Result, len(urls))
	for i, u := range urls {
		results[i] = Analyze(u)
	}
	return results
}

// riskFromScore maps a numeric score to a RiskLevel.
func riskFromScore(score float64) RiskLevel {
	switch {
	case score < 0.15:
		return RiskNone
	case score < 0.30:
		return RiskLow
	case score < 0.55:
		return RiskMedium
	case score < 0.80:
		return RiskHigh
	default:
		return RiskCritical
	}
}

// buildReasons generates human-readable strings for each detected signal.
func buildReasons(r Result) []string {
	var reasons []string

	// Entropy reasons.
	if r.Entropy > 4.5 {
		reasons = append(reasons, fmt.Sprintf("high Shannon entropy (%.2f) suggests randomized/obfuscated URL", r.Entropy))
	}

	// Unicode reasons.
	u := r.UnicodeFlags
	if u.MixedScripts {
		reasons = append(reasons, fmt.Sprintf("mixed Unicode scripts detected: %v", u.ScriptsFound))
	}
	if u.HomoglyphCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d homoglyph character(s) found (look-alike characters from other scripts)", u.HomoglyphCount))
	}
	if u.InvisibleCharCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d invisible/zero-width character(s) detected", u.InvisibleCharCount))
	}
	if u.NonASCIIRatio > 0.1 {
		reasons = append(reasons, fmt.Sprintf("%.0f%% of characters are non-ASCII", u.NonASCIIRatio*100))
	}

	// Structure reasons.
	s := r.StructureFlags
	if s.HasIPAddress {
		reasons = append(reasons, "URL uses an IP address instead of a domain name")
	}
	if s.HasPortNumber {
		reasons = append(reasons, "URL specifies a non-standard port")
	}
	if s.ExcessiveSubdomains {
		reasons = append(reasons, fmt.Sprintf("excessive subdomains (%d levels)", s.SubdomainCount))
	}
	if s.ExcessivePathDepth {
		reasons = append(reasons, fmt.Sprintf("excessive path depth (%d segments)", s.PathDepth))
	}
	if s.HasDoubleEncoding {
		reasons = append(reasons, "double percent-encoding detected (possible evasion)")
	}
	if s.EncodedCharRatio > 0.1 {
		reasons = append(reasons, fmt.Sprintf("high percent-encoding ratio (%.0f%%)", s.EncodedCharRatio*100))
	}
	if s.SuspiciousTLD {
		reasons = append(reasons, "domain uses a TLD commonly associated with abuse")
	}
	if s.HasAtSign {
		reasons = append(reasons, "URL contains '@' in authority section (possible credential phishing)")
	}
	if s.ExcessiveLength {
		reasons = append(reasons, fmt.Sprintf("URL is unusually long (%d characters)", s.Length))
	}

	return reasons
}
