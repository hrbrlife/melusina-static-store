package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type unreadBodyProbe struct{ reads int }

func (p *unreadBodyProbe) Read(_ []byte) (int, error) { p.reads++; return 0, io.EOF }

func TestPublicPublishHeaderAuthBeforeBodyAndExactBodyBinding(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "header-operator", cfg.LicenseNFTMint, cfg.Domain)
	pub := newTestIdentity(t, "header-publisher", randPubkeyB58(t), "publisher.example.org")
	svc := newTestService(t, cfg, newMockChainReader(), op)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	now := time.Now().UTC().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	release := mustJSON(t, f.rel)
	signed := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish", now, 5*time.Minute, "header-positive")
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString(raw)
	makeProbe := func(value string) (*httptest.ResponseRecorder, *unreadBodyProbe) {
		probe := &unreadBodyProbe{}
		r := httptest.NewRequest(http.MethodPost, "/publish", probe)
		if value != "" {
			r.Header.Set(publisherEnvelopeHeader, value)
		}
		w := httptest.NewRecorder()
		svc.handlePublish(w, r)
		return w, probe
	}
	{
		probe := &unreadBodyProbe{}
		r := httptest.NewRequest(http.MethodPost, "/publish", probe)
		r.Header.Set(publisherEnvelopeHeader, header)
		w := httptest.NewRecorder()
		if !svc.requirePublisherHeader(w, r, "/publish") || probe.reads != 0 {
			t.Fatalf("PUBLISH_HEADER_POSITIVE_REFUSED: %d %s reads=%d", w.Code, w.Body.String(), probe.reads)
		}
	}
	if w, probe := makeProbe(""); w.Code != http.StatusUnauthorized || probe.reads != 0 || !strings.Contains(w.Body.String(), "check=envelope_header") {
		t.Fatalf("PUBLISH_MISSING_HEADER_BODY_READ: %d %s reads=%d", w.Code, w.Body.String(), probe.reads)
	}
	wrongRoute := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", now, 5*time.Minute, "wrong-route")
	wrongRaw, _ := json.Marshal(wrongRoute)
	if w, probe := makeProbe(base64.RawURLEncoding.EncodeToString(wrongRaw)); w.Code != http.StatusUnauthorized || probe.reads != 0 || !strings.Contains(w.Body.String(), "check=envelope_purpose") {
		t.Fatalf("PUBLISH_WRONG_HEADER_ROUTE_BODY_READ: %d %s reads=%d", w.Code, w.Body.String(), probe.reads)
	}
	tampered := signed
	tampered.Payload.Target = "/publish/stage"
	tamperedRaw, _ := json.Marshal(tampered)
	if w, probe := makeProbe(base64.RawURLEncoding.EncodeToString(tamperedRaw)); w.Code != http.StatusUnauthorized || probe.reads != 0 || !strings.Contains(w.Body.String(), "check=envelope_header") {
		t.Fatalf("PUBLISH_UNSIGNED_HEADER_MUTATION_BODY_READ: %d %s reads=%d", w.Code, w.Body.String(), probe.reads)
	}
	stale := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish", now.Add(-20*time.Minute), 5*time.Minute, "stale-header")
	staleRaw, _ := json.Marshal(stale)
	if w, probe := makeProbe(base64.RawURLEncoding.EncodeToString(staleRaw)); w.Code != http.StatusUnauthorized || probe.reads != 0 {
		t.Fatalf("PUBLISH_EXPIRED_HEADER_BODY_READ: %d %s reads=%d", w.Code, w.Body.String(), probe.reads)
	}
	other := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish", now, 5*time.Minute, "different-body")
	body := jsonPublishBody(t, other, release, f.spk, f.metadata)
	r := httptest.NewRequest(http.MethodPost, "/publish", bytes.NewReader(body.Bytes()))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(publisherEnvelopeHeader, header)
	w := httptest.NewRecorder()
	svc.handlePublish(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "check=envelope_header_body_mismatch") {
		t.Fatalf("PUBLISH_CHANGED_BODY_ENVELOPE_ACCEPTED: %d %s", w.Code, w.Body.String())
	}
}

func TestCXGStoreInstallerHeaderWindowKeepsAppWindowTight(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "cxg-window-operator", cfg.LicenseNFTMint, cfg.Domain)
	pub := newTestIdentity(t, "cxg-window-publisher", randPubkeyB58(t), "publisher.example.org")
	svc := newTestService(t, cfg, newMockChainReader(), op)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	now := time.Now().UTC().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	release := mustJSON(t, f.rel)
	check := func(signedTarget, checkedRoute string, issued time.Time, ttl time.Duration, nonce string) (bool, string) {
		t.Helper()
		signed := signPublishForRoute(t, pub, op.Public(), f.spk, release, signedTarget, issued, ttl, nonce)
		raw, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, checkedRoute, http.NoBody)
		r.Header.Set(publisherEnvelopeHeader, base64.RawURLEncoding.EncodeToString(raw))
		w := httptest.NewRecorder()
		return svc.requirePublisherHeader(w, r, checkedRoute), w.Body.String()
	}
	if accepted, detail := check("/publish/installer", "/publish/installer", now, 48*time.Minute, "cxg-installer-48m"); !accepted {
		t.Fatalf("CXG_INSTALLER_48M_HEADER_REFUSED: %s", detail)
	}
	for _, item := range []struct {
		name, signedTarget, checkedRoute, refusal string
		issued                                    time.Time
		ttl                                       time.Duration
	}{
		{"app-40m", "/publish", "/publish", "check=envelope_header_ttl", now, 40 * time.Minute},
		{"installer-expired", "/publish/installer", "/publish/installer", "check=envelope_header_ttl", now.Add(-49 * time.Minute), 48 * time.Minute},
		{"installer-wrong-route", "/publish", "/publish/installer", "check=envelope_purpose", now, 48 * time.Minute},
	} {
		if accepted, detail := check(item.signedTarget, item.checkedRoute, item.issued, item.ttl, "cxg-"+item.name); accepted || !strings.Contains(detail, item.refusal) {
			t.Fatalf("CXG_%s_HEADER_MUTATION_ACCEPTED: %s", item.name, detail)
		}
	}
}
