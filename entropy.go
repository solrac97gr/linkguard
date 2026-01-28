package linkguard

import "math"

// ShannonEntropy calculates the Shannon entropy of a string.
// Higher entropy indicates more randomness, which is common in obfuscated URLs.
// A normal English URL typically has entropy between 3.0-4.5.
// Suspicious/random URLs often exceed 4.5-5.0.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// NormalizedEntropy returns the Shannon entropy normalized to [0, 1].
// Normalization divides by log2 of the number of unique characters.
func NormalizedEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	unique := make(map[rune]struct{})
	for _, r := range s {
		unique[r] = struct{}{}
	}
	if len(unique) <= 1 {
		return 0
	}

	return ShannonEntropy(s) / math.Log2(float64(len(unique)))
}

// entropyScore converts raw Shannon entropy into a 0.0-1.0 suspicion score.
// Thresholds are calibrated for typical URL strings.
func entropyScore(entropy float64) float64 {
	// Normal URLs: ~3.0–4.0 entropy
	// Mildly suspicious: 4.0–4.5
	// Suspicious: 4.5–5.0
	// Highly suspicious: >5.0
	switch {
	case entropy <= 3.5:
		return 0.0
	case entropy <= 4.0:
		return 0.1
	case entropy <= 4.5:
		return 0.3
	case entropy <= 5.0:
		return 0.6
	case entropy <= 5.5:
		return 0.8
	default:
		return 1.0
	}
}
