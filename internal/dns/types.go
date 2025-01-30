package dns

type QueryType uint16

const (
    TypeA    QueryType = 1
    TypeAAAA QueryType = 28
    TypeMX   QueryType = 15
    TypeTXT  QueryType = 16
)

type DNSRecord struct {
    Name     string
    Type     QueryType
    Value    string
    TTL      uint32
    Priority uint16 // For MX records
}

type AnalysisResult struct {
    Records     []DNSRecord
    Age         time.Duration
    Similarity  float64
    Historical  []DNSRecord
    LastUpdated time.Time
}
