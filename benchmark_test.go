//go:build benchmark
// +build benchmark

package linkguard

import (
	"testing"
)

// Benchmark a simple, clean URL.
func BenchmarkAnalyze_Simple(b *testing.B) {
	analyzer := NewAnalyzer(DefaultMethods()...)
	url := "https://google.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.Analyze(url)
	}
}

// Benchmark a URL with multiple suspicious flags.
func BenchmarkAnalyze_Suspicious(b *testing.B) {
	analyzer := NewAnalyzer(DefaultMethods()...)
	url := "https://microsоft.com-verify.tk/login@192.168.1.1"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.Analyze(url)
	}
}

// Benchmark individual analysis methods.
func BenchmarkAnalysisMethods(b *testing.B) {
	methods := DefaultMethods()
	url := "https://microsоft.com-verify.tk/login@192.168.1.1"

	for _, method := range methods {
		b.Run(method.Name(), func(b *testing.B) {
			result := &Result{}
			for i := 0; i < b.N; i++ {
				_ = method.Analyze(url, result)
			}
		})
	}
}
