package dns

import (
    "context"
    "sync"
    "time"
    
    "github.com/miekg/dns"
    "github.com/DarkStalkr/LinkTracer2.0/pkg/similarity"
)

type Analyzer struct {
    client *dns.Client
    config *Config
    cache  *Cache
    mu     sync.RWMutex
}

type Cache struct {
    items map[string]CacheItem
    mu    sync.RWMutex
}

type CacheItem struct {
    Result    AnalysisResult
    ExpiresAt time.Time
}

func NewAnalyzer(config *Config) *Analyzer {
    if config == nil {
        config = DefaultConfig()
    }
    
    return &Analyzer{
        client: &dns.Client{
            Timeout: config.Timeout,
        },
        config: config,
        cache: &Cache{
            items: make(map[string]CacheItem),
        },
    }
}

func (a *Analyzer) Analyze(ctx context.Context, domain string, targetDomain string) (*AnalysisResult, error) {
    // Check cache first
    if a.config.CacheEnabled {
        if result, ok := a.checkCache(domain); ok {
            return result, nil
        }
    }

    // Create result channels for different record types
    results := make(chan []DNSRecord, 4)
    errors := make(chan error, 4)

    // Query different record types concurrently
    go a.queryRecords(ctx, domain, TypeA, results, errors)
    go a.queryRecords(ctx, domain, TypeAAAA, results, errors)
    go a.queryRecords(ctx, domain, TypeMX, results, errors)
    go a.queryRecords(ctx, domain, TypeTXT, results, errors)

    // Collect results
    var allRecords []DNSRecord
    for i := 0; i < 4; i++ {
        select {
        case records := <-results:
            allRecords = append(allRecords, records...)
        case err := <-errors:
            return nil, err
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }

    // Calculate similarity score with target domain
    simScore := similarity.LevenshteinDistance(domain, targetDomain)

    result := &AnalysisResult{
        Records:    allRecords,
        Similarity: simScore,
        LastUpdated: time.Now(),
    }

    // Cache the result
    if a.config.CacheEnabled {
        a.cacheResult(domain, result)
    }

    return result, nil
}

func (a *Analyzer) queryRecords(ctx context.Context, domain string, qtype QueryType, results chan<- []DNSRecord, errors chan<- error) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(domain), uint16(qtype))
    m.RecursionDesired = true

    var records []DNSRecord

    for _, server := range a.config.NameServers {
        r, _, err := a.client.ExchangeContext(ctx, m, server)
        if err != nil {
            continue
        }

        for _, ans := range r.Answer {
            record := DNSRecord{
                Name: ans.Header().Name,
                Type: QueryType(ans.Header().Rrtype),
                TTL:  uint32(ans.Header().Ttl),
            }

            switch v := ans.(type) {
            case *dns.A:
                record.Value = v.A.String()
            case *dns.AAAA:
                record.Value = v.AAAA.String()
            case *dns.MX:
                record.Value = v.Mx
                record.Priority = v.Preference
            case *dns.TXT:
                record.Value = strings.Join(v.Txt, " ")
            }

            records = append(records, record)
        }

        break // Successfully got records from this server
    }

    results <- records
}

