package server

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var queryComplexityRejectedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "dnsscienced_query_complexity_rejected_total",
	Help: "Total DNS queries refused because they exceeded the configured complexity score.",
})

// QueryComplexityConfig bounds syntactically valid but unusually expensive
// query combinations before policy, authoritative, or recursive processing.
type QueryComplexityConfig struct {
	Enabled        bool `yaml:"enabled"`
	MaxScore       int  `yaml:"max_score"`
	ANYCost        int  `yaml:"any_cost"`
	DNSSECCost     int  `yaml:"dnssec_cost"`
	LongNameCost   int  `yaml:"long_name_cost"`
	EDNSOptionCost int  `yaml:"edns_option_cost"`
}

func defaultQueryComplexityConfig() QueryComplexityConfig {
	return QueryComplexityConfig{
		Enabled:        true,
		MaxScore:       20,
		ANYCost:        6,
		DNSSECCost:     4,
		LongNameCost:   5,
		EDNSOptionCost: 1,
	}
}

func normalizeQueryComplexityConfig(cfg QueryComplexityConfig) (QueryComplexityConfig, error) {
	if !cfg.Enabled {
		return cfg, nil
	}
	defaults := defaultQueryComplexityConfig()
	if cfg.MaxScore == 0 {
		cfg.MaxScore = defaults.MaxScore
	}
	if cfg.ANYCost == 0 {
		cfg.ANYCost = defaults.ANYCost
	}
	if cfg.DNSSECCost == 0 {
		cfg.DNSSECCost = defaults.DNSSECCost
	}
	if cfg.LongNameCost == 0 {
		cfg.LongNameCost = defaults.LongNameCost
	}
	if cfg.EDNSOptionCost == 0 {
		cfg.EDNSOptionCost = defaults.EDNSOptionCost
	}
	values := []struct {
		name  string
		value int
	}{
		{"max_score", cfg.MaxScore},
		{"any_cost", cfg.ANYCost},
		{"dnssec_cost", cfg.DNSSECCost},
		{"long_name_cost", cfg.LongNameCost},
		{"edns_option_cost", cfg.EDNSOptionCost},
	}
	for _, field := range values {
		if field.value < 1 || field.value > 10_000 {
			return QueryComplexityConfig{}, fmt.Errorf("query_complexity.%s must be between 1 and 10000", field.name)
		}
	}
	return cfg, nil
}

func queryComplexityScore(msg *dns.Msg, cfg QueryComplexityConfig) int {
	if msg == nil || len(msg.Question) != 1 {
		return 0
	}
	score := 1
	question := msg.Question[0]
	switch question.Qtype {
	case dns.TypeANY:
		score += cfg.ANYCost
	case dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3:
		score += cfg.DNSSECCost
	}
	if len(question.Name) > 192 || len(dns.SplitDomainName(question.Name)) > 20 {
		score += cfg.LongNameCost
	}
	if opt := msg.IsEdns0(); opt != nil {
		score += len(opt.Option) * cfg.EDNSOptionCost
		if opt.Do() {
			score += cfg.DNSSECCost
		}
	}
	// QUERY messages do not use Answer or Authority sections. Penalize them
	// heavily, along with non-OPT/TSIG additional records, instead of allowing
	// unusual payloads to reach plugins and recursive processing.
	score += (len(msg.Answer) + len(msg.Ns)) * cfg.MaxScore
	for _, rr := range msg.Extra {
		switch rr.Header().Rrtype {
		case dns.TypeOPT, dns.TypeTSIG:
		default:
			score += cfg.MaxScore
		}
	}
	return score
}
