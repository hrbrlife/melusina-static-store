package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

type catalogRowFlight struct {
	done chan struct{}
	err  error
}

func catalogRowKey(candidate catalogGateCandidate) string {
	rowHash := sha256.Sum256(candidate.raw)
	return strings.ToLower(candidate.app.rel.AppHash) + ":" + metadataAppID(candidate.app.metadata) + ":" + hex.EncodeToString(rowHash[:])
}

func artifactRowKey(appHash, appID string, rel ReleaseJSON) string {
	raw, _ := json.Marshal(rel) // ReleaseJSON contains only fixed JSON-compatible fields.
	rowHash := sha256.Sum256(raw)
	return "artifact:" + strings.ToLower(strings.TrimSpace(appHash)) + ":" + appID + ":" + hex.EncodeToString(rowHash[:])
}

func (g *serveGate) catalogRowNeedsRead(key string) bool {
	if g.catalogRowTTL <= 0 {
		return true
	}
	g.catalogRowMu.Lock()
	defer g.catalogRowMu.Unlock()
	if at, ok := g.catalogRowVerdict[key]; ok && !g.now().Before(at) && g.now().Sub(at) < g.catalogRowTTL {
		return false
	}
	return g.catalogRowFlights[key] == nil
}

// verifyCatalogRow shares an exact positive row verdict across pointer, index
// and package requests for at most the configured short TTL. A changed row
// key, refusal or expired verdict still reaches the full product chain gate.
func (g *serveGate) verifyCatalogRow(ctx context.Context, key string, verify func() error) error {
	if g.catalogRowTTL <= 0 {
		return verify()
	}
	g.catalogRowMu.Lock()
	if at, ok := g.catalogRowVerdict[key]; ok && !g.now().Before(at) && g.now().Sub(at) < g.catalogRowTTL {
		g.catalogRowMu.Unlock()
		return ctx.Err()
	}
	if flight := g.catalogRowFlights[key]; flight != nil {
		g.catalogRowMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-flight.done:
			if err := ctx.Err(); err != nil {
				return err
			}
			return flight.err
		}
	}
	flight := &catalogRowFlight{done: make(chan struct{})}
	g.catalogRowFlights[key] = flight
	g.catalogRowMu.Unlock()

	err := verify()
	g.catalogRowMu.Lock()
	if err == nil {
		if len(g.catalogRowVerdict) >= 4096 {
			g.catalogRowVerdict = make(map[string]time.Time)
		}
		g.catalogRowVerdict[key] = g.now()
	}
	flight.err = err
	delete(g.catalogRowFlights, key)
	close(flight.done)
	g.catalogRowMu.Unlock()
	return err
}
