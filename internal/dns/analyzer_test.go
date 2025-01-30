// internal/dns/analyzer_test.go
package dns

import (
    "context"
    "testing"
    "time"
)

func TestNewAnalyzer(t *testing.T) {
    // Test with nil config (should use default)
    analyzer := NewAnalyzer(nil)
    if analyzer == nil {
        t.Fatal("Expected non-nil analyzer with nil config")
    }
    if analyzer.config == nil {
        t.Fatal("Expected non-nil default config")
    }

    // Test with custom config
    customConfig := &Config{
        Timeout:     2 * time.Second,
        RetryCount:  2,
        NameServers: []string{"1.1.1.1:53"},
    }
    analyzer = NewAnalyzer(customConfig)
    if analyzer.config != customConfig {
        t.Fatal("Expected custom config to be used")
    }
}

func TestAnalyzer_Analyze(t *testing.T) {
    analyzer := NewAnalyzer(nil)
    ctx := context.Background()

    tests := []struct {
        name         string
        domain      string
        targetDomain string
        wantErr     bool
    }{
        {
            name:         "Valid domain google.com",
            domain:      "google.com",
            targetDomain: "google.com",
            wantErr:     false,
        },
        {
            name:         "Invalid domain",
            domain:      "thisisaninvalid",  // No TLD
            targetDomain: "google.com",
            wantErr:     true,
        },
        {
            name:         "Empty domain",
            domain:      "",
            targetDomain: "google.com",
            wantErr:     true,
        },
        {
            name:         "Invalid characters",
            domain:      "test@domain.com",
            targetDomain: "google.com",
            wantErr:     true,
        },
        {
            name:         "Too long domain",
            domain:      "a" + string(make([]byte, 256)) + ".com",
            targetDomain: "google.com",
            wantErr:     true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := analyzer.Analyze(ctx, tt.domain, tt.targetDomain)
            if (err != nil) != tt.wantErr {
                t.Errorf("Analyze() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !tt.wantErr && result == nil {
                t.Error("Expected non-nil result for successful analysis")
            }
            if !tt.wantErr && result != nil {
                if result.Similarity < 0 || result.Similarity > 1 {
                    t.Error("Similarity score should be between 0 and 1")
                }
            }
        })
    }
}
