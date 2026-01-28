// Package unicode provides Unicode-based attack detection for URLs.
package unicode

import (
	"sort"
	"unicode"

	"github.com/solrac97gr/linkguard/types"
)

// analysis performs Unicode-based attack detection on URLs.
type analysis struct {
	weightValue float64
}

// New creates a new Unicode analyzer with the specified weight.
//
// The weight determines the importance of Unicode analysis in the final score.
// Standard weight is 0.35 (35%).
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

// Analyze implements the AnalysisMethod interface for Unicode analysis.
func (a *analysis) Analyze(rawURL string, result *types.Result) float64 {
	result.UnicodeFlags = Analyze(rawURL)
	return Score(result.UnicodeFlags)
}

// Weight returns the weight of Unicode analysis.
func (a *analysis) Weight() float64 {
	return a.weightValue
}

// Name returns the name of this analysis method.
func (a *analysis) Name() string {
	return "Unicode Analysis"
}

// Common homoglyphs: characters from non-Latin scripts that visually resemble ASCII letters.
// Map from suspicious rune to the ASCII character it imitates.
var homoglyphs = map[rune]rune{
	// Cyrillic homoglyphs
	'\u0410': 'A', // А -> A
	'\u0412': 'B', // В -> B
	'\u0421': 'C', // С -> C
	'\u0415': 'E', // Е -> E
	'\u041D': 'H', // Н -> H
	'\u041A': 'K', // К -> K
	'\u041C': 'M', // М -> M
	'\u041E': 'O', // О -> O
	'\u0420': 'P', // Р -> P
	'\u0422': 'T', // Т -> T
	'\u0425': 'X', // Х -> X
	'\u0430': 'a', // а -> a
	'\u0435': 'e', // е -> e
	'\u043E': 'o', // о -> o
	'\u0440': 'p', // р -> p
	'\u0441': 'c', // с -> c
	'\u0443': 'y', // у -> y
	'\u0445': 'x', // х -> x
	'\u0455': 's', // ѕ -> s
	'\u0456': 'i', // і -> i
	'\u0458': 'j', // ј -> j

	// Greek homoglyphs
	'\u0391': 'A', // Α -> A
	'\u0392': 'B', // Β -> B
	'\u0395': 'E', // Ε -> E
	'\u0397': 'H', // Η -> H
	'\u0399': 'I', // Ι -> I
	'\u039A': 'K', // Κ -> K
	'\u039C': 'M', // Μ -> M
	'\u039D': 'N', // Ν -> N
	'\u039F': 'O', // Ο -> O
	'\u03A1': 'P', // Ρ -> P
	'\u03A4': 'T', // Τ -> T
	'\u03A5': 'Y', // Υ -> Y
	'\u03A7': 'X', // Χ -> X
	'\u03B1': 'a', // α -> a (less similar but used)
	'\u03BF': 'o', // ο -> o

	// Fullwidth Latin (used in CJK contexts)
	'\uFF21': 'A', // Ａ
	'\uFF22': 'B', // Ｂ
	'\uFF23': 'C', // Ｃ
	'\uFF24': 'D', // Ｄ
	'\uFF25': 'E', // Ｅ
	'\uFF41': 'a', // ａ
	'\uFF42': 'b', // ｂ
	'\uFF43': 'c', // ｃ
	'\uFF44': 'd', // ｄ
	'\uFF45': 'e', // ｅ

	// Other common look-alikes
	'\u0131': 'i', // ı (dotless i)
	'\u1D00': 'A', // ᴀ (small cap A)
	'\u0261': 'g', // ɡ (script g)
	'\u029C': 'H', // ʜ (small cap H)
}

// Zero-width and invisible Unicode characters commonly used for obfuscation.
var invisibleChars = map[rune]bool{
	'\u200B': true, // Zero-width space
	'\u200C': true, // Zero-width non-joiner
	'\u200D': true, // Zero-width joiner
	'\u200E': true, // Left-to-right mark
	'\u200F': true, // Right-to-left mark
	'\u2060': true, // Word joiner
	'\u2061': true, // Function application
	'\u2062': true, // Invisible times
	'\u2063': true, // Invisible separator
	'\u2064': true, // Invisible plus
	'\uFEFF': true, // Zero-width no-break space (BOM)
	'\u00AD': true, // Soft hyphen
	'\u034F': true, // Combining grapheme joiner
	'\u061C': true, // Arabic letter mark
	'\u115F': true, // Hangul choseong filler
	'\u1160': true, // Hangul jungseong filler
	'\u17B4': true, // Khmer vowel inherent AQ
	'\u17B5': true, // Khmer vowel inherent AA
	'\u180E': true, // Mongolian vowel separator
}

// scriptName returns a simplified script name for a rune.
func scriptName(r rune) string {
	switch {
	case r <= 0x007F:
		return "ASCII"
	// Check for full-width characters, which are often used in homoglyph attacks.
	// They belong to the "Halfwidth and Fullwidth Forms" block.
	case r >= 0xFF00 && r <= 0xFFEF:
		return "Other"
	case unicode.Is(unicode.Latin, r):
		return "Latin"
	case unicode.Is(unicode.Cyrillic, r):
		return "Cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "Greek"
	case unicode.Is(unicode.Han, r):
		return "Han"
	case unicode.Is(unicode.Arabic, r):
		return "Arabic"
	case unicode.Is(unicode.Devanagari, r):
		return "Devanagari"
	case unicode.Is(unicode.Hiragana, r):
		return "Hiragana"
	case unicode.Is(unicode.Katakana, r):
		return "Katakana"
	case unicode.Is(unicode.Thai, r):
		return "Thai"
	default:
		if unicode.IsLetter(r) {
			return "Other"
		}
		return ""
	}
}

// Analyze inspects a URL string for suspicious Unicode patterns.
func Analyze(url string) types.UnicodeReport {
	report := types.UnicodeReport{}

	scripts := make(map[string]bool)
	totalChars := 0
	nonASCII := 0

	for _, r := range url {
		totalChars++

		if r > 0x7F {
			nonASCII++
		}

		if _, ok := homoglyphs[r]; ok {
			report.HomoglyphCount++
		}

		if invisibleChars[r] {
			report.InvisibleCharCount++
		}

		s := scriptName(r)
		if s != "" {
			scripts[s] = true
		}
	}

	if totalChars > 0 {
		report.NonASCIIRatio = float64(nonASCII) / float64(totalChars)
	}

	for s := range scripts {
		report.ScriptsFound = append(report.ScriptsFound, s)
	}

	// Sort scripts for deterministic output
	sort.Strings(report.ScriptsFound)

	// Mixed scripts: having letter scripts beyond ASCII/Latin is suspicious in URLs.
	letterScripts := 0
	hasLatinOrASCII := false
	for s := range scripts {
		switch s {
		case "ASCII", "Latin":
			hasLatinOrASCII = true
		default:
			letterScripts++
		}
	}
	report.MixedScripts = letterScripts > 0 && hasLatinOrASCII

	return report
}

// Score converts the unicode report into a 0.0-1.0 suspicion score.
func Score(r types.UnicodeReport) float64 {
	score := 0.0

	if r.MixedScripts {
		score += 0.4
	}

	// Homoglyphs are a strong signal.
	switch {
	case r.HomoglyphCount >= 3:
		score += 0.5
	case r.HomoglyphCount >= 1:
		score += 0.4
	}

	// Invisible characters are almost always malicious in URLs.
	switch {
	case r.InvisibleCharCount >= 3:
		score += 0.5
	case r.InvisibleCharCount >= 1:
		score += 0.3
	}

	// High non-ASCII ratio.
	if r.NonASCIIRatio > 0.3 {
		score += 0.2
	} else if r.NonASCIIRatio > 0.1 {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}
