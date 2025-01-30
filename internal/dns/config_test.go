package dns

import (
    "testing"
    "time"
)

func TestDefaultConfig(t *testing.T) {
    config := DefaultConfig()

    if config == nil {
        t.Fatal("DefaultConfig() returned nil")
    }

    if config.Timeout != 5*time.Second {
        t.Errorf("Expected timeout 5s, got %v", config.Timeout)
    }

    if config.RetryCount != 3 {
        t.Errorf("Expected retry count 3, got %d", config.RetryCount)
    }

    if len(config.NameServers) != 2 {
        t.Errorf("Expected 2 nameservers, got %d", len(config.NameServers))
    }

    expectedServers := []string{"8.8.8.8:53", "8.8.4.4:53"}
    for i, server := range expectedServers {
        if config.NameServers[i] != server {
            t.Errorf("Expected nameserver %s, got %s", server, config.NameServers[i])
        }
    }
}

