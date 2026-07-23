package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type nameserverResult struct {
	response   *dns.Msg
	nameserver string
	err        error
}

// queryNameservers returns the first valid response. It starts one query
// immediately, hedges additional servers after the configured delay, and starts
// replacements immediately when an attempt fails.
func (r *Recursive) queryNameservers(
	ctx context.Context,
	nameservers []string,
	qname string,
	qtype, qclass uint16,
) (*dns.Msg, string, error) {
	if len(nameservers) == 0 {
		return nil, "", ErrNoNameservers
	}

	parallelism := min(r.cfg.NameserverParallelism, len(nameservers))
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan nameserverResult, parallelism)
	next := 0
	active := 0
	launch := func() {
		nameserver := nameservers[next]
		next++
		active++
		go func() {
			response, err := r.queryNameserver(queryCtx, nameserver, qname, qtype, qclass)
			if err == nil && isRetryableNameserverResponse(response) {
				err = fmt.Errorf("retryable response code %s", dns.RcodeToString[response.Rcode])
			}
			if err != nil {
				err = fmt.Errorf("%s: %w", nameserver, err)
			}
			results <- nameserverResult{response: response, nameserver: nameserver, err: err}
		}()
	}

	launch()
	var timer *time.Timer
	var hedge <-chan time.Time
	scheduleHedge := func() {
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer = nil
		}
		hedge = nil
		if next >= len(nameservers) || active >= parallelism {
			return
		}
		if r.cfg.NameserverHedgeDelay == 0 {
			for next < len(nameservers) && active < parallelism {
				launch()
			}
			return
		}
		timer = time.NewTimer(r.cfg.NameserverHedgeDelay)
		hedge = timer.C
	}
	scheduleHedge()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	var lastErr error
	for active > 0 {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case result := <-results:
			active--
			if result.err == nil {
				return result.response, result.nameserver, nil
			}
			lastErr = result.err
			if err := ctx.Err(); err != nil {
				return nil, "", err
			}
			if next < len(nameservers) {
				launch()
			}
			scheduleHedge()
		case <-hedge:
			timer = nil
			hedge = nil
			if err := ctx.Err(); err != nil {
				return nil, "", err
			}
			if next < len(nameservers) && active < parallelism {
				launch()
			}
			scheduleHedge()
		}
	}

	if lastErr == nil {
		lastErr = ErrNoNameservers
	}
	return nil, "", lastErr
}

func isRetryableNameserverResponse(response *dns.Msg) bool {
	if response == nil {
		return true
	}
	switch response.Rcode {
	case dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented:
		return true
	default:
		return false
	}
}
