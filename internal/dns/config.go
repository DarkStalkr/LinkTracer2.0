package dns

import "time"

type Config struct {
    Timeout      time.Duration
    RetryCount   int
    NameServers  []string
    CacheEnabled bool
    CacheTTL     time.Duration
}

func DefaultConfig() *Config {
    return &Config{
        Timeout:      5 * time.Second,
        RetryCount:   3,
        NameServers:  []string{"8.8.8.8:53", "8.8.4.4:53"},
        CacheEnabled: true,
        CacheTTL:    1 * time.Hour,
    }
}
