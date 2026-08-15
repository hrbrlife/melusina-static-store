/*
 * static_store — the Melusina App Bazaar store SPA (Tier 3 public tool).
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 Melusina Coop LU & Melusina Colorado LCA (joint co-owners).
 * Licensed under the GNU Affero General Public License v3.0-or-later; see
 * LICENSE for the full text and NOTICE for the Melusina brand reservation (M11).
 */
import React, { useEffect, useMemo, useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { format, formatDistanceToNow } from "date-fns";

/* Self-hosted fonts — no CDN */
import "@fontsource/orbitron/400.css";
import "@fontsource/orbitron/600.css";
import "@fontsource/orbitron/700.css";
import "@fontsource/orbitron/800.css";
import "@fontsource/orbitron/900.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "@fontsource/jetbrains-mono/700.css";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
import "@fontsource/inter/800.css";
import {
  BAZAAR_MARK_ICON_PATH,
  appIconPath,
  isExplicitlyIconless,
} from "./app-icon-map.js";

// Self-hosted origin: every catalog asset AND the app-install package-download
// URL resolve from the bazaar origin that served this SPA (the market popup is
// opened from Sandstorm's appMarketUrl = the root bazaar, which serves
// /packages|/apps|/icons|/images|/screenshots). The retired gh-pages origin
// (hrbrlife.github.io/melusina-static-store) is DELETED — bazaar is the sole
// origin (DEPLOY DOCTRINE); no stale fallback (greenfield).
const APP_INDEX_BASE = window.location.origin;
const LOGO_URL = `${APP_INDEX_BASE}/icons/melulogo-cyan.svg`;

/* ─── helpers ──────────────────────────────────────────────────────────────── */

const sanitizeHost = (h) => {
  if (!h) return "";
  const t = h.trim();
  return (!/^https?:\/\//i.test(t) ? `https://${t}` : t).replace(/\/+$/, "");
};

// Validate that a sanitized host is parseable and has a real hostname.
// Returns "" on valid, otherwise a short, user-actionable reason.
// `localhost` and bare-host shapes used by dev/LAN are allowed.
const hostValidationError = (raw) => {
  const t = (raw || "").trim();
  if (!t) return "Enter a server URL.";
  let u;
  try { u = new URL(sanitizeHost(t)); }
  catch { return "Not a valid URL — example: example.melusina-os.org"; }
  if (!u.hostname) return "Server address is missing a hostname.";
  if (/\s/.test(u.hostname)) return "Hostname cannot contain spaces.";
  return "";
};

const fmtDate = (v) => {
  if (!v) return "—";
  let ts = typeof v === "number" ? v : Date.parse(v);
  if (Number.isNaN(ts)) return String(v);
  // Second-precision timestamps (10 digits) need to be converted to ms.
  if (typeof v === "number" && v < 1e12) ts = v * 1000;
  return format(ts, "MMM d, yyyy");
};

const timeAgo = (v) => {
  if (!v) return null;
  let ts = typeof v === "number" ? v : Date.parse(v);
  if (Number.isNaN(ts)) return null;
  if (typeof v === "number" && v < 1e12) ts = v * 1000;
  try { return formatDistanceToNow(ts, { addSuffix: true }); } catch { return null; }
};

// The sidecar derives updatedAt from RELEASE.json's signedAtUnix when it
// assembles a published row. createdAt is source metadata and must never be
// presented as a promotion/update timestamp in the Bazaar.
const signedPromotionAt = (app) => app?.updatedAt ?? null;

const screenshotUrl = (appId, shot) => {
  const file = typeof shot === "string" ? shot : shot.url || "";
  if (file.startsWith("screenshots/")) {
    return `${APP_INDEX_BASE}/screenshots/${appId}/${file.replace("screenshots/", "")}`;
  }
  return `${APP_INDEX_BASE}/screenshots/${appId}/${file}`;
};

const shotCaption = (shot) =>
  typeof shot === "string" ? "" : shot.caption || "";

const installUrl = (host, app) => {
  const h = sanitizeHost(host);
  if (!h || !app.packageId) return null;
  const pkg = app.packageUrl || `${APP_INDEX_BASE}/packages/${app.packageId}`;
  return `${h}/install/${app.packageId}?url=${encodeURIComponent(pkg)}`;
};

// A runtime contract is a release-bound *test plan*, not evidence that the
// test has run. Keep that distinction visible: older cards are explicitly
// uncertified, while newer cards still need their post-install visible UI and
// sidecar probes recorded before anyone may call them launch-ready.
const runtimeContractInfo = (app) => {
  const rc = app?.runtimeContract;
  if (rc?.status === "declared") {
    return {
      label: "runtime proof pending",
      detail: "This release declares its visible launch and sidecar checks; the real post-install proof is still required.",
      color: T.yellow,
    };
  }
  return {
    label: "runtime uncertified",
    detail: rc?.reason || "This legacy release predates the release-bound runtime-contract gate.",
    color: T.magenta,
  };
};

/* ─── pbay.app jurisdiction servers ──────────────────────────────────────────────── */

const PBAY_SERVERS = [
  { code: 'LU', flag: '🇱🇺', name: 'Luxembourg', domain: 'lu.pbay.app', region: 'Europe' },
  { code: 'CH', flag: '🇨🇭', name: 'Switzerland', domain: 'ch.pbay.app', region: 'Europe' },
  { code: 'DE', flag: '🇩🇪', name: 'Germany', domain: 'de.pbay.app', region: 'Europe' },
  { code: 'FR', flag: '🇫🇷', name: 'France', domain: 'fr.pbay.app', region: 'Europe' },
  { code: 'NL', flag: '🇳🇱', name: 'Netherlands', domain: 'nl.pbay.app', region: 'Europe' },
  { code: 'FI', flag: '🇫🇮', name: 'Finland', domain: 'fi.pbay.app', region: 'Europe' },
  { code: 'IS', flag: '🇮🇸', name: 'Iceland', domain: 'is.pbay.app', region: 'Europe' },
  { code: 'US', flag: '🇺🇸', name: 'United States', domain: 'us.pbay.app', region: 'Americas' },
  { code: 'CA', flag: '🇨🇦', name: 'Canada', domain: 'ca.pbay.app', region: 'Americas' },
  { code: 'SG', flag: '🇸🇬', name: 'Singapore', domain: 'sg.pbay.app', region: 'Asia-Pacific' },
  { code: 'JP', flag: '🇯🇵', name: 'Japan', domain: 'jp.pbay.app', region: 'Asia-Pacific' },
];

/* pbay / private server localStorage helpers */
const PBAY_KEY = 'melusina_pbay_servers';
const PRIV_KEY = 'melusina_private_servers';

const getPbayServers = () => {
  try {
    const raw = localStorage.getItem(PBAY_KEY);
    if (!raw) return [];
    return JSON.parse(raw) || [];
  } catch { return []; }
};
const addPbayServer = (srv) => {
  const list = getPbayServers().filter((s) => s.code !== srv.code);
  list.unshift(srv);
  localStorage.setItem(PBAY_KEY, JSON.stringify(list.slice(0, 20)));
};
const removePbayServer = (code) => {
  const list = getPbayServers().filter((s) => s.code !== code);
  localStorage.setItem(PBAY_KEY, JSON.stringify(list));
};
const setPbayServer = (srv) => { addPbayServer(srv); };

const getPrivateServers = () => {
  try { return JSON.parse(localStorage.getItem(PRIV_KEY) || '[]'); } catch { return []; }
};
const addPrivateServer = (url) => {
  const list = getPrivateServers().filter((s) => s !== url);
  list.unshift(url);
  localStorage.setItem(PRIV_KEY, JSON.stringify(list.slice(0, 20)));
};
const removePrivateServer = (url) => {
  const list = getPrivateServers().filter((s) => s !== url);
  localStorage.setItem(PRIV_KEY, JSON.stringify(list));
};
const isPbayHost = (host) => {
  const domain = sanitizeHost(host).replace(/^https?:\/\//i, '').toLowerCase();
  return PBAY_SERVERS.find((s) => domain === s.domain || domain.endsWith('.' + s.domain));
};

/* ─── Get Melusina Modal ───────────────────────────────────────────────────────── */

function GetMelusinaModal({ onClose }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(8,6,20,0.85)',
      backdropFilter: 'blur(12px)', WebkitBackdropFilter: 'blur(12px)',
    }} onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()} style={{
        width: 560, maxWidth: '92vw', maxHeight: '85dvh', overflowY: 'auto', WebkitOverflowScrolling: 'touch',
        background: 'linear-gradient(160deg, rgba(22,16,48,0.98), rgba(14,10,32,0.98))',
        border: `1px solid ${T.cyan}33`,
        borderRadius: T.radius,
        boxShadow: `0 0 60px ${T.accentGlow}, 0 30px 80px rgba(0,0,0,.5)`,
        animation: 'pop .2s ease-out',
      }}>
        {/* header */}
        <div style={{
          padding: '28px 28px 20px',
          borderBottom: `1px solid ${T.purple}22`,
          background: `linear-gradient(135deg, ${T.cyan}08, ${T.magenta}06)`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{
              fontSize: 18, fontWeight: 800, color: T.cyan,
              fontFamily: "'Orbitron', sans-serif",
              textShadow: `0 0 12px ${T.accentGlow}`,
            }}>Get Melusina</div>
            <button onClick={onClose} style={{
              background: 'none', border: 'none', color: T.textDim, fontSize: 22,
              cursor: 'pointer', padding: 4, lineHeight: 1,
            }}>×</button>
          </div>
          <div style={{ fontSize: 12, color: T.textSec, marginTop: 6, lineHeight: 1.6 }}>
            Two ways to run Melusina apps — choose what fits your needs.
          </div>
        </div>

        <div style={{ padding: '24px 28px 28px', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* pbay.app option */}
          <div style={{
            padding: 24, background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.cyan}33`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span style={{ fontSize: 24 }}>🌐</span>
              <div>
                <div style={{
                  fontSize: 15, fontWeight: 800, color: T.cyan,
                  fontFamily: "'Orbitron', sans-serif",
                  textShadow: `0 0 8px ${T.accentGlow}`,
                }}>pbay.app</div>
                <div style={{
                  fontSize: 10, fontWeight: 700, color: T.green,
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: '.08em', textTransform: 'uppercase',
                }}>MANAGED HOSTING</div>
              </div>
            </div>
            <div style={{ fontSize: 13, color: T.textSec, lineHeight: 1.8, marginBottom: 16 }}>
              Fully managed hosting — sign up, pick a jurisdiction, and start using apps immediately.
              Your data stays in the country you choose. Each server is <strong style={{ color: T.text }}>legally,
              physically, and operationally isolated</strong>.
            </div>
            <ul style={{ margin: 0, padding: '0 0 0 18px', fontSize: 12, color: T.textSec, lineHeight: 2 }}>
              <li>No server setup required</li>
              <li>Jurisdiction-isolated — pick your country</li>
              <li>Automatic updates and backups</li>
              <li>Export your Pearls anytime — no lock-in</li>
            </ul>
            <a href="https://pbay.app" target="_blank" rel="noopener noreferrer" style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              width: '100%', padding: '14px 20px', marginTop: 18,
              background: `linear-gradient(135deg, ${T.cyan}18, ${T.magenta}12)`,
              border: `1px solid ${T.cyan}55`,
              borderRadius: T.radiusSm, cursor: 'pointer',
              color: T.cyan, fontSize: 12, fontWeight: 700,
              fontFamily: "'Orbitron', sans-serif",
              letterSpacing: '.08em', textTransform: 'uppercase',
              textShadow: `0 0 8px ${T.accentGlow}`,
              textDecoration: 'none', transition: 'all .2s',
            }}
              onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 25px ${T.accentGlow}`; }}
              onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; }}
            >Go to pbay.app ↗</a>
          </div>

          {/* Self-hosted option */}
          <div style={{
            padding: 24, background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.magenta}33`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span style={{ fontSize: 24 }}>🖥️</span>
              <div>
                <div style={{
                  fontSize: 15, fontWeight: 800, color: T.magenta,
                  fontFamily: "'Orbitron', sans-serif",
                  textShadow: `0 0 8px ${T.magentaGlow}`,
                }}>Self-Hosted</div>
                <div style={{
                  fontSize: 10, fontWeight: 700, color: T.yellow,
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: '.08em', textTransform: 'uppercase',
                }}>YOUR SERVER, YOUR RULES</div>
              </div>
            </div>
            <div style={{ fontSize: 13, color: T.textSec, lineHeight: 1.8, marginBottom: 16 }}>
              Install Melusina on your own hardware or VPS. Full control over your data, networking,
              and security. Run air-gapped or on the open internet — your choice.
            </div>
            <ul style={{ margin: 0, padding: '0 0 0 18px', fontSize: 12, color: T.textSec, lineHeight: 2 }}>
              <li>Full root access and control</li>
              <li>Air-gapped or internet-connected</li>
              <li>No third-party dependencies</li>
              <li>Community and commercial support available</li>
            </ul>
            <a href="https://melusina-os.org/install" target="_blank" rel="noopener noreferrer" style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              width: '100%', padding: '14px 20px', marginTop: 18,
              background: `linear-gradient(135deg, ${T.magenta}18, ${T.purple}12)`,
              border: `1px solid ${T.magenta}55`,
              borderRadius: T.radiusSm, cursor: 'pointer',
              color: T.magenta, fontSize: 12, fontWeight: 700,
              fontFamily: "'Orbitron', sans-serif",
              letterSpacing: '.08em', textTransform: 'uppercase',
              textShadow: `0 0 8px ${T.magentaGlow}`,
              textDecoration: 'none', transition: 'all .2s',
            }}
              onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 25px ${T.magentaGlow}`; }}
              onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; }}
            >Install Guide on melusina-os.org ↗</a>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Jurisdiction Picker Modal ────────────────────────────────────────────────── */

function JurisdictionModal({ onSelect, onClose }) {
  const regions = useMemo(() => {
    const map = {};
    PBAY_SERVERS.forEach((s) => {
      if (!map[s.region]) map[s.region] = [];
      map[s.region].push(s);
    });
    return Object.entries(map);
  }, []);

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(8,6,20,0.85)',
      backdropFilter: 'blur(12px)', WebkitBackdropFilter: 'blur(12px)',
    }} onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()} style={{
        width: 560, maxWidth: '92vw', maxHeight: '82dvh', overflowY: 'auto', WebkitOverflowScrolling: 'touch',
        background: 'linear-gradient(160deg, rgba(22,16,48,0.98), rgba(14,10,32,0.98))',
        border: `1px solid ${T.cyan}33`,
        borderRadius: T.radius,
        boxShadow: `0 0 60px ${T.accentGlow}, 0 30px 80px rgba(0,0,0,.5)`,
        padding: 0,
        animation: 'pop .2s ease-out',
      }}>
        {/* header */}
        <div style={{
          padding: '28px 32px 20px', borderBottom: `1px solid ${T.purple}22`,
          background: `linear-gradient(135deg, ${T.cyan}08, ${T.magenta}06)`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{
                fontSize: 18, fontWeight: 800, color: T.cyan,
                fontFamily: "'Orbitron', sans-serif",
                textShadow: `0 0 12px ${T.accentGlow}`,
                marginBottom: 4,
              }}>Pick Your Jurisdiction</div>
              <div style={{
                fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: '.04em',
              }}>Professionally hosted by the team behind melusina-os.org</div>
            </div>
            <button onClick={onClose} style={{
              background: 'none', border: 'none', color: T.textDim, fontSize: 22,
              cursor: 'pointer', padding: 4, lineHeight: 1,
            }}>×</button>
          </div>
        </div>

        {/* explanation */}
        <div style={{
          padding: '20px 32px', borderBottom: `1px solid ${T.purple}15`,
          background: T.yellow + '06',
        }}>
          <div style={{
            fontSize: 12, color: T.textSec, lineHeight: 1.8,
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            <strong style={{ color: T.yellow }}>Each pbay.app server is legally, physically, and operationally
            isolated to a single jurisdiction.</strong> Your data, compute, and legal agreements stay
            within the borders of the jurisdiction you choose. No cross-border replication, no
            shared infrastructure between regions.
          </div>
          <div style={{
            fontSize: 11, color: T.textDim, lineHeight: 1.7, marginTop: 10,
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            This is for SaaS pbay hosting only. You can export and move your Pearls to a private
            Melusina installation at any time — no lock-in.
          </div>
        </div>

        {/* server grid by region */}
        <div style={{ padding: '24px 32px 32px' }}>
          {regions.map(([region, servers]) => (
            <div key={region} style={{ marginBottom: 20 }}>
              <div style={{
                fontSize: 10, fontWeight: 700, color: T.textDim, marginBottom: 10,
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: '.12em', textTransform: 'uppercase',
              }}>{region}</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }}>
                {servers.map((srv) => (
                  <button key={srv.code} onClick={() => onSelect(srv)} style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '14px 18px', background: T.surface,
                    border: `1px solid ${T.cyan}22`,
                    borderRadius: T.radiusSm, cursor: 'pointer',
                    transition: 'all .2s', textAlign: 'left',
                  }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.borderColor = T.cyan + '66';
                      e.currentTarget.style.boxShadow = `0 0 18px ${T.accentGlow}`;
                      e.currentTarget.style.background = T.cyan + '11';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.borderColor = T.cyan + '22';
                      e.currentTarget.style.boxShadow = 'none';
                      e.currentTarget.style.background = T.surface;
                    }}
                  >
                    <span style={{ fontSize: 24 }}>{srv.flag}</span>
                    <div>
                      <div style={{
                        fontSize: 13, fontWeight: 700, color: T.text,
                        fontFamily: "'Orbitron', sans-serif",
                      }}>{srv.code} — {srv.domain}</div>
                      <div style={{
                        fontSize: 11, color: T.cyan, fontFamily: "'JetBrains Mono', monospace",
                      }}>{srv.name}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ─── Install Destination Modal ────────────────────────────────────────────────── */

function InstallModal({ app, onClose }) {
  const [section, setSection] = useState('pbay');
  const [showJurisdiction, setShowJurisdiction] = useState(false);
  const [pbayServers, setPbayServersState] = useState(() => getPbayServers());
  const [privateServers, setPrivateServers] = useState(() => getPrivateServers());
  const [newPrivate, setNewPrivate] = useState('');
  const [addingPrivate, setAddingPrivate] = useState(false);
  const [privateError, setPrivateError] = useState('');
  const [installError, setInstallError] = useState('');

  const doInstall = useCallback((host) => {
    const h = sanitizeHost(host);
    if (!h) {
      setInstallError("Enter a Melusina server URL before installing.");
      return;
    }
    if (!app.packageId) {
      setInstallError(`Cannot install "${app.name || 'this app'}": package is missing from the catalog.`);
      return;
    }
    const pkg = app.packageUrl || `${APP_INDEX_BASE}/packages/${app.packageId}`;
    const opened = window.open(`${h}/install/${app.packageId}?url=${encodeURIComponent(pkg)}`, '_blank', 'noopener,noreferrer');
    if (opened) opened.opener = null;
    onClose();
  }, [app, onClose]);

  const selectPbay = useCallback((srv) => {
    addPbayServer(srv);
    setPbayServersState(getPbayServers());
    setShowJurisdiction(false);
    doInstall(`https://${srv.domain}`);
  }, [doInstall]);

  const addAndInstallPrivate = useCallback(() => {
    const err = hostValidationError(newPrivate);
    if (err) { setPrivateError(err); return; }
    const h = sanitizeHost(newPrivate);
    addPrivateServer(h);
    setPrivateServers(getPrivateServers());
    setNewPrivate('');
    setPrivateError('');
    setAddingPrivate(false);
    doInstall(h);
  }, [newPrivate, doInstall]);

  if (showJurisdiction) {
    return <JurisdictionModal onSelect={selectPbay} onClose={() => setShowJurisdiction(false)} />;
  }

  const sectionTabStyle = (active) => ({
    flex: 1, padding: '14px 12px', border: 'none',
    background: active ? T.cyan + '15' : 'transparent',
    color: active ? T.cyan : T.textDim,
    fontSize: 12, fontWeight: 700, cursor: 'pointer',
    fontFamily: "'Orbitron', sans-serif",
    letterSpacing: '.06em', textTransform: 'uppercase',
    borderBottom: active ? `2px solid ${T.cyan}` : `2px solid transparent`,
    transition: 'all .2s',
  });

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9998,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(8,6,20,0.85)',
      backdropFilter: 'blur(12px)', WebkitBackdropFilter: 'blur(12px)',
    }} onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()} style={{
        width: 520, maxWidth: '92vw', maxHeight: '82dvh', overflowY: 'auto', WebkitOverflowScrolling: 'touch',
        background: 'linear-gradient(160deg, rgba(22,16,48,0.98), rgba(14,10,32,0.98))',
        border: `1px solid ${T.cyan}33`,
        borderRadius: T.radius,
        boxShadow: `0 0 60px ${T.accentGlow}, 0 30px 80px rgba(0,0,0,.5)`,
        animation: 'pop .2s ease-out',
      }}>
        {/* header */}
        <div style={{
          padding: '24px 28px 18px',
          borderBottom: `1px solid ${T.purple}22`,
          background: `linear-gradient(135deg, ${T.cyan}08, ${T.magenta}06)`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{
                fontSize: 16, fontWeight: 800, color: T.cyan,
                fontFamily: "'Orbitron', sans-serif",
                textShadow: `0 0 10px ${T.accentGlow}`,
                marginBottom: 3,
              }}>Install {app.name}</div>
              <div style={{
                fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace",
              }}>Choose your deployment destination</div>
            </div>
            <button onClick={onClose} style={{
              background: 'none', border: 'none', color: T.textDim, fontSize: 22,
              cursor: 'pointer', padding: 4, lineHeight: 1,
            }}>×</button>
          </div>
        </div>

        {/* section tabs */}
        <div style={{ display: 'flex', borderBottom: `1px solid ${T.purple}22` }}>
          <button style={sectionTabStyle(section === 'pbay')} onClick={() => { setSection('pbay'); setInstallError(''); }}>
            🌐 pbay.app
          </button>
          <button style={sectionTabStyle(section === 'private')} onClick={() => { setSection('private'); setInstallError(''); }}>
            🖥️ Private Servers
          </button>
        </div>

        {installError && (
          <div role="alert" style={{
            margin: '14px 28px 0', padding: '10px 14px',
            background: T.magenta + '14',
            border: `1px solid ${T.magenta}55`,
            borderRadius: T.radiusSm,
            fontSize: 12, color: T.magenta,
            fontFamily: "'JetBrains Mono', monospace",
            textShadow: `0 0 4px ${T.magentaGlow}`,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10,
          }}>
            <span>{installError}</span>
            <button onClick={() => setInstallError('')} aria-label="Dismiss" style={{
              background: 'none', border: 'none', color: T.magenta, fontSize: 16,
              cursor: 'pointer', padding: '0 4px', lineHeight: 1,
            }}>×</button>
          </div>
        )}

        {/* ─── pbay.app section ─── */}
        {section === 'pbay' && (
          <div style={{ padding: '24px 28px 28px' }}>
            {pbayServers.length > 0 && (
              <div style={{ marginBottom: 20 }}>
                <div style={{
                  fontSize: 10, fontWeight: 700, color: T.textDim, marginBottom: 10,
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: '.1em', textTransform: 'uppercase',
                }}>YOUR PBAY SERVERS</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {pbayServers.map((srv) => (
                    <div key={srv.code} style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '12px 16px', background: T.surface,
                      border: `1px solid ${T.cyan}22`,
                      borderRadius: T.radiusSm, transition: 'all .2s',
                    }}
                      onMouseEnter={(e) => { e.currentTarget.style.borderColor = T.cyan + '44'; }}
                      onMouseLeave={(e) => { e.currentTarget.style.borderColor = T.cyan + '22'; }}
                    >
                      <span style={{ fontSize: 22, flexShrink: 0 }}>{srv.flag}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{
                          fontSize: 13, fontWeight: 700, color: T.text,
                          fontFamily: "'Orbitron', sans-serif",
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>{srv.code} — {srv.domain}</div>
                        <div style={{
                          fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace",
                        }}>{srv.name}</div>
                      </div>
                      <button onClick={() => doInstall(`https://${srv.domain}`)} style={{
                        padding: '6px 16px', borderRadius: 3,
                        background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}15)`,
                        border: `1px solid ${T.cyan}44`,
                        color: T.cyan, fontSize: 10, fontWeight: 700,
                        fontFamily: "'Orbitron', sans-serif",
                        letterSpacing: '.06em', cursor: 'pointer',
                        textShadow: `0 0 6px ${T.accentGlow}`,
                        transition: 'all .2s', flexShrink: 0,
                      }}
                        onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 12px ${T.accentGlow}`; }}
                        onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; }}
                      >↓ INSTALL</button>
                      <button onClick={() => { removePbayServer(srv.code); setPbayServersState(getPbayServers()); }} style={{
                        background: 'none', border: 'none', color: T.textDim, fontSize: 14,
                        cursor: 'pointer', padding: '2px 6px', lineHeight: 1,
                        transition: 'color .2s', flexShrink: 0,
                      }}
                        onMouseEnter={(e) => { e.currentTarget.style.color = T.magenta; }}
                        onMouseLeave={(e) => { e.currentTarget.style.color = T.textDim; }}
                      >×</button>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div style={{
              padding: 20, background: T.yellow + '08', borderRadius: T.radiusSm,
              border: `1px solid ${T.yellow}33`, marginBottom: 16,
            }}>
              <div style={{
                fontSize: 12, fontWeight: 700, color: T.yellow, marginBottom: 6,
                fontFamily: "'Orbitron', sans-serif",
              }}>Jurisdiction-Isolated Hosting</div>
              <div style={{
                fontSize: 11, color: T.textSec, lineHeight: 1.7,
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                Each pbay.app server is <strong style={{ color: T.text }}>legally, physically, and
                operationally isolated</strong> to a single jurisdiction.
              </div>
            </div>
            <button onClick={() => setShowJurisdiction(true)} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
              width: '100%', padding: '14px 20px',
              background: `linear-gradient(135deg, ${T.cyan}18, ${T.magenta}12)`,
              border: `1px solid ${T.cyan}55`,
              borderRadius: T.radiusSm, cursor: 'pointer',
              color: T.cyan, fontSize: 12, fontWeight: 700,
              fontFamily: "'Orbitron', sans-serif",
              letterSpacing: '.08em', textTransform: 'uppercase',
              textShadow: `0 0 8px ${T.accentGlow}`,
              boxShadow: `0 0 15px ${T.accentGlow}`,
              transition: 'all .2s',
            }}
              onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 30px ${T.accentGlow}`; e.currentTarget.style.transform = 'scale(1.02)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.boxShadow = `0 0 15px ${T.accentGlow}`; e.currentTarget.style.transform = 'none'; }}
            >🌐 {pbayServers.length > 0 ? 'Add Another Jurisdiction' : 'Choose Jurisdiction'}</button>
          </div>
        )}

        {/* ─── Private Servers section ─── */}
        {section === 'private' && (
          <div style={{ padding: '24px 28px 28px' }}>
            {privateServers.length > 0 && (
              <div style={{ marginBottom: 20 }}>
                <div style={{
                  fontSize: 10, fontWeight: 700, color: T.textDim, marginBottom: 10,
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: '.1em', textTransform: 'uppercase',
                }}>RECENT SERVERS</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {privateServers.map((srv) => (
                    <div key={srv} style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '12px 16px', background: T.surface,
                      border: `1px solid ${T.border}`,
                      borderRadius: T.radiusSm,
                      transition: 'all .2s',
                    }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = T.cyan + '44';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = T.border;
                      }}
                    >
                      <span style={{
                        fontSize: 14, color: T.green, flexShrink: 0,
                      }}>🖥️</span>
                      <span style={{
                        flex: 1, fontSize: 12, color: T.text,
                        fontFamily: "'JetBrains Mono', monospace", fontWeight: 600,
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>{srv}</span>
                      <button onClick={() => doInstall(srv)} style={{
                        padding: '6px 16px', borderRadius: 3,
                        background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}15)`,
                        border: `1px solid ${T.cyan}44`,
                        color: T.cyan, fontSize: 10, fontWeight: 700,
                        fontFamily: "'Orbitron', sans-serif",
                        letterSpacing: '.06em', cursor: 'pointer',
                        textShadow: `0 0 6px ${T.accentGlow}`,
                        transition: 'all .2s',
                      }}
                        onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 12px ${T.accentGlow}`; }}
                        onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; }}
                      >INSTALL</button>
                      <button onClick={() => { removePrivateServer(srv); setPrivateServers(getPrivateServers()); }} style={{
                        background: 'none', border: 'none', color: T.textDim, fontSize: 14,
                        cursor: 'pointer', padding: '2px 6px', lineHeight: 1,
                        transition: 'color .2s',
                      }}
                        onMouseEnter={(e) => { e.currentTarget.style.color = T.magenta; }}
                        onMouseLeave={(e) => { e.currentTarget.style.color = T.textDim; }}
                      >×</button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {addingPrivate ? (
              <div style={{
                padding: 18, background: T.surface, borderRadius: T.radiusSm,
                border: `1px solid ${T.cyan}33`,
              }}>
                <label style={{
                  display: 'block', fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '.1em', color: T.cyan, marginBottom: 8,
                  fontFamily: "'Orbitron', sans-serif",
                  textShadow: `0 0 6px ${T.accentGlow}`,
                }}>Server Address</label>
                <input type="url" placeholder="https://example.melusina-os.org" value={newPrivate}
                  onChange={(e) => { setNewPrivate(e.target.value); if (privateError) setPrivateError(''); }} autoFocus
                  onKeyDown={(e) => e.key === 'Enter' && addAndInstallPrivate()}
                  aria-invalid={!!privateError}
                  aria-describedby={privateError ? 'private-server-error' : undefined}
                  style={{
                    width: '100%', padding: '12px 14px',
                    background: 'rgba(192,132,252,0.06)',
                    border: `1px solid ${privateError ? T.magenta + '99' : T.purple + '33'}`,
                    borderRadius: T.radiusSm, color: T.text,
                    fontSize: 13, outline: 'none',
                    fontFamily: "'JetBrains Mono', monospace",
                    transition: 'border-color .2s, box-shadow .2s',
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = privateError ? T.magenta + 'cc' : T.cyan + '88';
                    e.target.style.boxShadow = privateError ? `0 0 15px ${T.magentaGlow}` : `0 0 15px ${T.accentGlow}`;
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = privateError ? T.magenta + '99' : T.purple + '33';
                    e.target.style.boxShadow = 'none';
                  }}
                />
                {privateError && (
                  <div id="private-server-error" role="alert" style={{
                    marginTop: 8, fontSize: 11, color: T.magenta,
                    fontFamily: "'JetBrains Mono', monospace",
                    textShadow: `0 0 4px ${T.magentaGlow}`,
                  }}>{privateError}</div>
                )}
                <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
                  <button onClick={addAndInstallPrivate} style={{
                    flex: 1, padding: '10px 16px', borderRadius: 3,
                    background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}15)`,
                    border: `1px solid ${T.cyan}55`,
                    color: T.cyan, fontSize: 11, fontWeight: 700,
                    fontFamily: "'Orbitron', sans-serif",
                    letterSpacing: '.06em', cursor: 'pointer',
                    textShadow: `0 0 8px ${T.accentGlow}`,
                    transition: 'all .2s',
                  }}
                    onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 15px ${T.accentGlow}`; }}
                    onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; }}
                  >↓ CONNECT & INSTALL</button>
                  <button onClick={() => { setAddingPrivate(false); setNewPrivate(''); }} style={{
                    padding: '10px 16px', borderRadius: 3,
                    background: 'transparent',
                    border: `1px solid ${T.border}`,
                    color: T.textDim, fontSize: 11, fontWeight: 600,
                    fontFamily: "'JetBrains Mono', monospace",
                    cursor: 'pointer', transition: 'all .2s',
                  }}>Cancel</button>
                </div>
              </div>
            ) : (
              <button onClick={() => setAddingPrivate(true)} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                width: '100%', padding: '14px 20px',
                background: T.surface, border: `1px dashed ${T.cyan}33`,
                borderRadius: T.radiusSm, cursor: 'pointer',
                color: T.cyan, fontSize: 12, fontWeight: 600,
                fontFamily: "'JetBrains Mono', monospace",
                transition: 'all .2s',
              }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = T.cyan + '66';
                  e.currentTarget.style.background = T.cyan + '08';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = T.cyan + '33';
                  e.currentTarget.style.background = T.surface;
                }}
              >+ Add Private Server</button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── palm beach sunset tokens ────────────────────────────────────────────── */

const T = {
  bg: "#110e24",
  bgAlt: "#1a1535",
  surface: "rgba(24, 18, 52, 0.72)",
  card: "rgba(28, 22, 58, 0.55)",
  cardHover: "rgba(42, 32, 78, 0.7)",
  border: "rgba(192, 132, 252, 0.1)",
  borderLight: "rgba(192, 132, 252, 0.06)",
  cyan: "#00e5ff",
  magenta: "#ff7eb3",
  green: "#4ade80",
  purple: "#c084fc",
  yellow: "#ffd166",
  peach: "#ffb86c",
  accentGlow: "rgba(0, 229, 255, 0.18)",
  magentaGlow: "rgba(255, 126, 179, 0.2)",
  greenGlow: "rgba(74, 222, 128, 0.15)",
  text: "#f0eaff",
  textSec: "#b0a3cc",
  textDim: "#6e5f8a",
  radius: 8,
  radiusSm: 6,
};

/* ─── global CSS ───────────────────────────────────────────────────────────── */

const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:17px;-webkit-text-size-adjust:100%}
body{
  font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:linear-gradient(170deg, #0e0b1f 0%, #1a1040 25%, #2a1550 45%, #251245 60%, #1a1040 78%, #110e24 100%);
  background-attachment:fixed;
  color:${T.text};
  overflow-x:hidden;
  min-height:100dvh;
}
a{color:${T.cyan};text-decoration:none}
a:hover{color:${T.magenta};text-shadow:0 0 8px ${T.magentaGlow}}
::selection{background:${T.accentGlow};color:${T.text}}

::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:${T.cyan}33;border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:${T.cyan}66}
html{scrollbar-color:${T.cyan}33 transparent;scrollbar-width:thin}

input,select,button{font:inherit;color:inherit}
img{display:block;max-width:100%}

body::before{
  content:'';position:fixed;inset:0;z-index:-2;
  background:
    radial-gradient(ellipse 140% 50% at 50% 108%, rgba(255,126,179,0.12), transparent 65%),
    radial-gradient(ellipse 90% 35% at 18% 80%, rgba(255,184,108,0.08), transparent 55%),
    radial-gradient(ellipse 110% 40% at 80% 85%, rgba(192,132,252,0.09), transparent 60%),
    radial-gradient(ellipse 70% 25% at 40% 12%, rgba(0,229,255,0.05), transparent 50%),
    radial-gradient(ellipse 50% 20% at 65% 5%, rgba(192,132,252,0.04), transparent 45%);
}
body::after{
  content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:
    radial-gradient(ellipse 700px 400px at 12% 18%, ${T.purple}0c, transparent),
    radial-gradient(ellipse 600px 500px at 85% 70%, ${T.magenta}0b, transparent),
    radial-gradient(ellipse 900px 350px at 50% 95%, rgba(255,184,108,0.07), transparent),
    radial-gradient(ellipse 500px 400px at 65% 35%, ${T.cyan}06, transparent),
    radial-gradient(ellipse 400px 300px at 35% 55%, rgba(192,132,252,0.05), transparent);
}

@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes pop{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:none}}
@keyframes glowPulse{
  0%,100%{box-shadow:0 0 5px ${T.purple}33,0 0 20px ${T.purple}11,inset 0 0 15px ${T.purple}08}
  50%{box-shadow:0 0 10px ${T.purple}55,0 0 40px ${T.purple}22,inset 0 0 25px ${T.purple}11}
}
@keyframes scanLine{
  0%{transform:translateY(-100%)}
  100%{transform:translateY(100%)}
}
@keyframes flicker{
  0%,100%{opacity:1}
  92%{opacity:1}
  93%{opacity:.7}
  94%{opacity:1}
  96%{opacity:.8}
  97%{opacity:1}
}

.cat-scroll::-webkit-scrollbar{display:none}
.cat-scroll{scrollbar-width:none}

.ss-strip{display:flex;gap:12px;overflow-x:auto;padding:4px 0 10px;scroll-snap-type:x mandatory;-webkit-overflow-scrolling:touch}
.ss-strip::-webkit-scrollbar{height:3px}
.ss-strip::-webkit-scrollbar-thumb{background:${T.cyan}44;border-radius:2px}
.ss-strip img{
  scroll-snap-align:start;border-radius:3px;
  border:1px solid ${T.border};cursor:pointer;
  transition:transform .2s,border-color .2s,box-shadow .2s;
  object-fit:cover;flex-shrink:0;
}
.ss-strip img:hover{
  transform:scale(1.03);border-color:${T.cyan};
  box-shadow:0 0 20px ${T.accentGlow},0 4px 16px rgba(0,0,0,.5);
}

.card-slideshow{position:relative;overflow:hidden;aspect-ratio:16/9;background:${T.bgAlt};border-radius:${T.radius}px ${T.radius}px 0 0}
.card-slideshow-track{display:flex;height:100%;transition:transform .35s cubic-bezier(.4,0,.2,1);will-change:transform}
.card-slideshow-slide{flex:0 0 100%;height:100%;display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden}
.card-slideshow-slide img{width:100%;height:100%;object-fit:cover}
.card-slideshow-icon{display:flex;align-items:center;justify-content:center;width:100%;height:100%;padding-bottom:18px;background:linear-gradient(135deg,${T.bgAlt},rgba(42,32,78,0.5))}
.card-slideshow-dots{position:absolute;bottom:8px;left:50%;transform:translateX(-50%);display:flex;gap:5px;z-index:4}
.card-slideshow-dot{width:6px;height:6px;border-radius:50%;border:none;padding:0;cursor:pointer;transition:all .25s;background:rgba(255,255,255,.35)}
.card-slideshow-dot.active{background:${T.cyan};box-shadow:0 0 6px ${T.cyan}88;width:16px;border-radius:3px}
.app-card-skeleton{animation:skeletonPulse 1.15s ease-in-out infinite}
@keyframes skeletonPulse{0%,100%{opacity:.35}50%{opacity:.75}}
@media (prefers-reduced-motion: reduce){.app-card-skeleton{animation:none;opacity:.5}}
.card-slideshow-nav{position:absolute;top:50%;transform:translateY(-50%);z-index:4;width:28px;height:28px;border-radius:50%;border:none;background:rgba(17,14,36,.7);color:${T.text};font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity .2s;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.card-slideshow:hover .card-slideshow-nav{opacity:1}
.card-slideshow-nav.prev{left:6px}
.card-slideshow-nav.next{right:6px}

.lightbox-overlay{
  position:fixed;inset:0;z-index:900;
  background:rgba(14,11,30,.92);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  display:flex;align-items:center;justify-content:center;
  animation:fadeIn .2s ease-out;cursor:zoom-out;
}
.lightbox-overlay img{
  max-width:92vw;max-height:88vh;border-radius:4px;
  box-shadow:0 0 60px ${T.accentGlow},0 20px 60px rgba(0,0,0,.7);
  border:1px solid ${T.cyan}44;
  animation:pop .2s ease-out;
}

@media(max-width:480px){html{font-size:15px}}

.neon-text{
  background:linear-gradient(135deg, ${T.cyan}, ${T.magenta});
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
  filter:drop-shadow(0 0 8px ${T.cyan}55) drop-shadow(0 0 20px ${T.magenta}33);
}

.detail-tabs{display:flex;gap:0;margin-bottom:28px;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none;border-bottom:1px solid ${T.cyan}15}
.detail-tabs::-webkit-scrollbar{display:none}
.detail-tab{
  padding:14px 24px;font-size:11px;font-weight:700;
  font-family:'Orbitron',sans-serif;letter-spacing:.1em;
  text-transform:uppercase;color:${T.textDim};
  cursor:pointer;background:none;border:none;
  border-bottom:2px solid transparent;
  transition:all .25s;white-space:nowrap;position:relative;
}
.detail-tab:hover{color:${T.textSec}}
.detail-tab.active{color:${T.cyan};border-bottom-color:${T.cyan};text-shadow:0 0 8px ${T.accentGlow}}

.md-body h2{font-size:22px;font-weight:800;color:${T.text};margin:28px 0 12px;font-family:'Orbitron',sans-serif;letter-spacing:.02em}
.md-body h2:first-child{margin-top:0}
.md-body h3{font-size:18px;font-weight:700;color:${T.cyan};margin:24px 0 10px;font-family:'Orbitron',sans-serif;text-shadow:0 0 6px ${T.accentGlow}}
.md-body h4{font-size:15px;font-weight:700;color:${T.magenta};margin:20px 0 8px;font-family:'Orbitron',sans-serif}
.md-body p{font-size:15px;line-height:1.8;color:${T.textSec};margin:0 0 12px}
.md-body ul{margin:0 0 16px 0;padding-left:0;list-style:none}
.md-body ul li{font-size:15px;line-height:1.8;color:${T.textSec};padding-left:18px;position:relative;margin-bottom:4px}
.md-body ul li::before{content:'▸';position:absolute;left:0;color:${T.cyan};font-size:13px;text-shadow:0 0 4px ${T.accentGlow}}
.md-body code{background:${T.cyan}11;color:${T.cyan};padding:2px 6px;border-radius:2px;font-size:0.9em;font-family:'JetBrains Mono',monospace}
.md-body a{color:${T.cyan};border-bottom:1px solid ${T.cyan}33}
.md-body strong{color:${T.text};font-weight:600}
.md-body h5{font-size:14px;font-weight:700;color:${T.yellow};margin:16px 0 6px;font-family:'Orbitron',sans-serif;text-transform:uppercase;letter-spacing:.06em}
.md-body hr{border:none;height:1px;background:linear-gradient(90deg,transparent,${T.cyan}44,${T.purple}44,transparent);margin:28px 0}
.md-body img{max-width:100%;border-radius:8px;border:1px solid ${T.border};margin:8px 0;display:block}
.md-table-wrap{overflow-x:auto;margin:16px 0;border-radius:8px;border:1px solid ${T.border}}
.md-table{width:100%;border-collapse:collapse;font-size:14px;font-family:'JetBrains Mono',monospace}
.md-table th{padding:10px 14px;text-align:left;font-weight:700;color:${T.cyan};background:${T.cyan}08;border-bottom:1px solid ${T.cyan}22;font-size:13px;text-transform:uppercase;letter-spacing:.06em;white-space:nowrap}
.md-table td{padding:9px 14px;color:${T.textSec};border-bottom:1px solid ${T.border};line-height:1.6}
.md-table tr:last-child td{border-bottom:none}
.md-table tr:hover td{background:${T.cyan}06}
.md-bq{border-left:3px solid ${T.cyan}44;padding:12px 20px;margin:16px 0;background:${T.cyan}06;border-radius:0 8px 8px 0}
.md-bq p{margin:0 0 4px;font-style:italic;color:${T.textSec}}
.md-body ol{margin:0 0 16px 0;padding-left:24px;list-style:decimal}
.md-body ol li{font-size:15px;line-height:1.8;color:${T.textSec};margin-bottom:4px}
.md-body ol li::marker{color:${T.cyan}}

@media(max-width:480px){.detail-tab{padding:12px 16px;font-size:10px;letter-spacing:.06em}}
@media(max-width:768px){.mobile-sticky-install{display:flex!important}}
`;

/* ─── small components ─────────────────────────────────────────────────────── */

function Badge({ children, neon }) {
  const base = neon || T.cyan;
  return (
    <span style={{
      display: "inline-block", padding: "4px 12px", fontSize: 11,
      fontFamily: "'JetBrains Mono', monospace",
      fontWeight: 600, letterSpacing: ".08em", textTransform: "uppercase",
      border: `1px solid ${base}44`,
      borderRadius: 2,
      background: `${base}11`,
      color: base,
      whiteSpace: "nowrap",
      textShadow: `0 0 6px ${base}44`,
    }}>
      {children}
    </span>
  );
}

function AppIcon({ app, size = 48 }) {
  const [failed, setFailed] = useState(false);
  const appId = typeof app?.appId === "string" ? app.appId : "";
  const iconless = isExplicitlyIconless(appId);
  const signedIcon = iconless ? null : appIconPath(appId);
  // The map is generated from the package's signed manifest. An explicitly
  // iconless app, an app added after this shell release, or a failed asset all
  // render the Bazaar mark — never a letter derived from mutable catalog text.
  const src = failed || !signedIcon ? BAZAAR_MARK_ICON_PATH : signedIcon;
  return (
    <img src={src} alt="" loading="lazy" onError={() => setFailed(true)}
      style={{
        width: size, height: size, borderRadius: T.radiusSm,
        objectFit: "contain", background: T.bgAlt, flexShrink: 0,
        border: `1px solid ${T.border}`,
      }}
    />
  );
}



/* ─── Card Slideshow ────────────────────────────────────────────────────────── */

function CardSlideshow({ app, shots }) {
  const [idx, setIdx] = useState(0);
  const total = 1 + shots.length; // icon + screenshots

  const startX = React.useRef(null);
  const onTouchStart = (e) => { startX.current = e.touches[0].clientX; };
  const onTouchEnd = (e) => {
    if (startX.current === null) return;
    const dx = e.changedTouches[0].clientX - startX.current;
    if (Math.abs(dx) > 40) {
      if (dx < 0 && idx < total - 1) setIdx(idx + 1);
      else if (dx > 0 && idx > 0) setIdx(idx - 1);
    }
    startX.current = null;
  };

  return (
    <div className="card-slideshow"
      onTouchStart={onTouchStart} onTouchEnd={onTouchEnd}>
      <div className="card-slideshow-track" style={{ transform: `translateX(-${idx * 100}%)` }}>
        {/* slide 0: app icon */}
        <div className="card-slideshow-slide">
          <div className="card-slideshow-icon">
            <AppIcon app={app} size={160} />
          </div>
        </div>
        {/* slides 1+: screenshots */}
        {shots.map((s, i) => (
          <div key={i} className="card-slideshow-slide">
            <img src={screenshotUrl(app.appId, s)}
              alt={shotCaption(s) || `Screenshot ${i + 1}`}
              loading="lazy"
              onError={(e) => { e.target.style.display = "none"; }}
            />
          </div>
        ))}
      </div>
      {/* dots */}
      {total > 1 && (
        <div className="card-slideshow-dots">
          {Array.from({ length: total }).map((_, i) => (
            <button key={i} className={`card-slideshow-dot${i === idx ? ' active' : ''}`}
              onClick={(e) => { e.stopPropagation(); setIdx(i); }} />
          ))}
        </div>
      )}
      {/* prev/next arrows */}
      {total > 1 && idx > 0 && (
        <button className="card-slideshow-nav prev"
          onClick={(e) => { e.stopPropagation(); setIdx(idx - 1); }}>‹</button>
      )}
      {total > 1 && idx < total - 1 && (
        <button className="card-slideshow-nav next"
          onClick={(e) => { e.stopPropagation(); setIdx(idx + 1); }}>›</button>
      )}
    </div>
  );
}

/* ─── App Card ─────────────────────────────────────────────────────────────── */

function AppCard({ app, onSelect, onInstall }) {
  const [hov, setHov] = useState(false);
  const shots = (app.screenshots || []).slice(0, 5);
  const updatedAgo = timeAgo(signedPromotionAt(app));
  const runtime = runtimeContractInfo(app);

  return (
    <div role="button" tabIndex={0}
      onClick={() => onSelect(app.appId)}
      onKeyDown={(e) => e.key === "Enter" && onSelect(app.appId)}
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{
        position: "relative",
        background: hov ? T.cardHover : T.card,
        border: `1px solid ${hov ? T.cyan + "55" : T.cyan + "18"}`,
        borderRadius: T.radius, cursor: "pointer",
        transition: "all .3s ease",
        transform: hov ? "translateY(-3px)" : "none",
        boxShadow: hov
          ? `0 0 25px ${T.accentGlow}, 0 10px 40px rgba(0,0,0,.3), 0 0 60px ${T.magentaGlow}, inset 0 0 30px ${T.purple}08`
          : `0 2px 10px rgba(0,0,0,.2), inset 0 0 20px ${T.purple}06`,
        backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
        display: "flex", flexDirection: "column",
        animation: "fadeUp .5s ease-out both",
        height: "100%", overflow: "hidden",
      }}
    >

      {/* scan line on hover */}
      {hov && (
        <div style={{
          position: "absolute", inset: 0, zIndex: 1, pointerEvents: "none",
          overflow: "hidden", borderRadius: T.radius,
        }}>
          <div style={{
            width: "100%", height: "2px",
            background: `linear-gradient(90deg, transparent, ${T.purple}33, ${T.magenta}22, transparent)`,
            animation: "scanLine 2s linear infinite",
          }} />
        </div>
      )}

      {/* slideshow: icon first, then screenshots */}
      <CardSlideshow app={app} shots={shots} />

      <div style={{ padding: "14px 16px 16px", display: "flex", flexDirection: "column", gap: 10, flex: 1, position: "relative", zIndex: 2 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h3 style={{
            fontSize: 16, fontWeight: 700, margin: 0,
            fontFamily: "'Orbitron', sans-serif",
            color: hov ? T.cyan : T.text,
            textShadow: hov ? `0 0 10px ${T.accentGlow}` : "none",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            transition: "color .3s, text-shadow .3s",
            letterSpacing: ".02em",
          }}>{app.name}</h3>
          {/* Version + updated ago */}
          <div style={{
            fontSize: 11, color: T.textDim, marginTop: 3,
            fontFamily: "'JetBrains Mono', monospace",
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <span>v{app.version || app.versionNumber || '—'}</span>
            {updatedAgo && <span style={{ opacity: 0.7 }}>· updated {updatedAgo}</span>}
          </div>
          {(app.shortDescription || app.summary) && (
            <p style={{
              fontSize: 14, color: T.textSec, margin: "6px 0 0", lineHeight: 1.5,
              display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical",
              overflow: "hidden",
            }}>
              <SimpleMarkdown text={app.shortDescription || app.summary} />
            </p>
          )}
        </div>

        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          gap: 8, marginTop: "auto",
        }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", minWidth: 0 }}>
            {(app.categories || []).slice(0, 2).map((c) => <Badge key={c}>{c}</Badge>)}
            <span title={runtime.detail}><Badge neon={runtime.color}>{runtime.label}</Badge></span>
            {getConnectivityBadges(app.appId).map((b, i) => (
              <Badge key={`conn-${i}`} neon={b.color === 'yellow' ? T.yellow : T.magenta}>{b.icon} {b.short}</Badge>
            ))}
          </div>
          <button
              onClick={(e) => { e.stopPropagation(); onInstall(app); }}
              style={{
                display: "inline-flex", alignItems: "center", gap: 5,
                padding: "10px 18px", minHeight: 44,
                background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`,
                border: `1px solid ${T.cyan}66`,
                color: T.cyan,
                fontFamily: "'Orbitron', sans-serif",
                fontWeight: 700, fontSize: 11, letterSpacing: ".1em",
                textTransform: "uppercase",
                borderRadius: T.radiusSm, whiteSpace: "nowrap",
                cursor: "pointer",
                textShadow: `0 0 8px ${T.accentGlow}`,
                boxShadow: `0 0 12px ${T.accentGlow}`,
                transition: "all .2s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = T.cyan + "33";
                e.currentTarget.style.boxShadow = `0 0 25px ${T.accentGlow}`;
                e.currentTarget.style.transform = "scale(1.05)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`;
                e.currentTarget.style.boxShadow = `0 0 12px ${T.accentGlow}`;
                e.currentTarget.style.transform = "none";
              }}
            >INSTALL</button>
        </div>
      </div>
    </div>
  );
}

/* ─── Screenshot Gallery ───────────────────────────────────────────────────── */

function ScreenshotGallery({ screenshots, appId }) {
  const [lightbox, setLightbox] = useState(null);

  const prev = useCallback(() => setLightbox((i) => (i > 0 ? i - 1 : (screenshots?.length || 1) - 1)), [screenshots]);
  const next = useCallback(() => setLightbox((i) => (i < (screenshots?.length || 1) - 1 ? i + 1 : 0)), [screenshots]);

  useEffect(() => {
    if (lightbox === null) return;
    const onKey = (e) => {
      if (e.key === 'Escape') { setLightbox(null); }
      else if (e.key === 'ArrowLeft' && (screenshots?.length || 0) > 1) { prev(); }
      else if (e.key === 'ArrowRight' && (screenshots?.length || 0) > 1) { next(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [lightbox, screenshots, prev, next]);

  if (!screenshots || screenshots.length === 0) return null;

  return (
    <>
      <div style={{ marginBottom: 28 }}>
        <div style={{
          fontSize: 10, fontWeight: 700, textTransform: "uppercase",
          letterSpacing: ".14em", color: T.cyan, marginBottom: 14,
          fontFamily: "'Orbitron', sans-serif",
          textShadow: `0 0 6px ${T.accentGlow}`,
          display: "flex", alignItems: "center", gap: 10,
        }}>
          <span style={{ width: 16, height: 1, background: T.cyan, boxShadow: `0 0 4px ${T.cyan}` }} />
          SCREENSHOTS
        </div>
        <div className="ss-strip">
          {screenshots.map((s, i) => (
            <div key={i} style={{ flexShrink: 0, display: "flex", flexDirection: "column", gap: 6 }}>
              <img src={screenshotUrl(appId, s)} alt={shotCaption(s) || `Screenshot ${i + 1}`}
                onClick={() => setLightbox(i)}
                style={{ width: 320, height: 200 }}
                onError={(e) => { e.target.parentElement.style.display = "none"; }}
              />
              {shotCaption(s) && (
                <span style={{ fontSize: 11, color: T.textDim, maxWidth: 320, lineHeight: 1.4,
                  fontFamily: "'JetBrains Mono', monospace" }}>
                  {shotCaption(s)}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>
      {lightbox !== null && (
        <div className="lightbox-overlay" role="dialog" aria-modal="true" aria-label="Screenshot lightbox" onClick={() => setLightbox(null)}>
          {screenshots.length > 1 && (
            <button onClick={(e) => { e.stopPropagation(); prev(); }} aria-label="Previous screenshot" style={{
              position: "absolute", left: 16, top: "50%", transform: "translateY(-50%)",
              background: "rgba(0,240,255,0.1)", border: `1px solid ${T.cyan}44`,
              color: T.cyan, width: 48, height: 48, borderRadius: 3,
              fontSize: 22, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
              textShadow: `0 0 8px ${T.cyan}`, transition: "all .2s",
              boxShadow: `0 0 15px ${T.accentGlow}`,
            }}
              onMouseEnter={(e) => { e.currentTarget.style.background = T.cyan + "22"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(0,240,255,0.1)"; }}
            >‹</button>
          )}
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, maxWidth: "92vw" }}>
            <img src={screenshotUrl(appId, screenshots[lightbox])}
              alt={shotCaption(screenshots[lightbox]) || `Screenshot ${lightbox + 1} of ${screenshots.length}`}
              onClick={(e) => e.stopPropagation()} style={{ cursor: "default" }} />
            {shotCaption(screenshots[lightbox]) && (
              <p style={{ color: T.cyan + "cc", fontSize: 13, textAlign: "center", maxWidth: 600,
                fontFamily: "'JetBrains Mono', monospace",
                textShadow: `0 0 6px ${T.accentGlow}`,
              }}>
                {shotCaption(screenshots[lightbox])}
              </p>
            )}
            <span style={{ color: T.textDim, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
              {lightbox + 1} / {screenshots.length}
            </span>
          </div>
          {screenshots.length > 1 && (
            <button onClick={(e) => { e.stopPropagation(); next(); }} aria-label="Next screenshot" style={{
              position: "absolute", right: 16, top: "50%", transform: "translateY(-50%)",
              background: "rgba(0,240,255,0.1)", border: `1px solid ${T.cyan}44`,
              color: T.cyan, width: 48, height: 48, borderRadius: 3,
              fontSize: 22, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
              textShadow: `0 0 8px ${T.cyan}`, transition: "all .2s",
              boxShadow: `0 0 15px ${T.accentGlow}`,
            }}
              onMouseEnter={(e) => { e.currentTarget.style.background = T.cyan + "22"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(0,240,255,0.1)"; }}
            >›</button>
          )}
        </div>
      )}
    </>
  );
}

/* ─── Simple Markdown ──────────────────────────────────────────────────────── */

function SimpleMarkdown({ text }) {
  if (!text) return null;
  const parseInline = (str) => {
    const parts = [];
    let rest = str, k = 0;
    while (rest.length > 0) {
      let m;
      if ((m = rest.match(/^!\[([^\]]*)\]\(([^)]+)\)/))) {
        parts.push(<img key={k++} src={m[2]} alt={m[1]} style={{ maxWidth: '100%', borderRadius: 6, margin: '4px 0' }} />);
        rest = rest.slice(m[0].length);
      } else if ((m = rest.match(/^\*\*(.+?)\*\*/))) {
        parts.push(<strong key={k++}>{m[1]}</strong>);
        rest = rest.slice(m[0].length);
      } else if ((m = rest.match(/^`(.+?)`/))) {
        parts.push(<code key={k++}>{m[1]}</code>);
        rest = rest.slice(m[0].length);
      } else if ((m = rest.match(/^\[(.+?)\]\((.+?)\)/))) {
        parts.push(<a key={k++} href={m[2]} target="_blank" rel="noopener noreferrer">{m[1]}</a>);
        rest = rest.slice(m[0].length);
      } else {
        const nx = rest.slice(1).search(/!\[|\*\*|`|\[/);
        if (nx >= 0) { parts.push(rest.slice(0, nx + 1)); rest = rest.slice(nx + 1); }
        else { parts.push(rest); rest = ''; }
      }
    }
    return parts.length === 1 && typeof parts[0] === 'string' ? parts[0] : parts;
  };
  const lines = text.split('\n');
  const els = [];
  let i = 0, k = 0;
  while (i < lines.length) {
    const ln = lines[i];
    /* headings */
    if (ln.startsWith('#### ')) { els.push(<h5 key={k++}>{parseInline(ln.slice(5))}</h5>); i++; }
    else if (ln.startsWith('### ')) { els.push(<h4 key={k++}>{parseInline(ln.slice(4))}</h4>); i++; }
    else if (ln.startsWith('## ')) { els.push(<h3 key={k++}>{parseInline(ln.slice(3))}</h3>); i++; }
    else if (ln.startsWith('# ')) { els.push(<h2 key={k++}>{parseInline(ln.slice(2))}</h2>); i++; }
    /* horizontal rule */
    else if (ln.trim().match(/^-{3,}$/) || ln.trim().match(/^\*{3,}$/)) { els.push(<hr key={k++} />); i++; }
    /* table */
    else if (ln.includes('|') && ln.trim().startsWith('|')) {
      const rows = [];
      while (i < lines.length && lines[i].includes('|') && lines[i].trim().startsWith('|')) {
        rows.push(lines[i]); i++;
      }
      const parseRow = (r) => r.split('|').slice(1, -1).map(c => c.trim());
      const header = parseRow(rows[0]);
      const isSep = (r) => parseRow(r).every(c => /^[:\-]+$/.test(c));
      const alignments = rows.length > 1 && isSep(rows[1])
        ? parseRow(rows[1]).map(c => c.startsWith(':') && c.endsWith(':') ? 'center' : c.endsWith(':') ? 'right' : 'left')
        : header.map(() => 'left');
      const dataStart = rows.length > 1 && isSep(rows[1]) ? 2 : 1;
      const dataRows = rows.slice(dataStart).map(parseRow);
      els.push(
        <div key={k++} className="md-table-wrap">
          <table className="md-table">
            <thead><tr>{header.map((h, j) => <th key={j} style={{ textAlign: alignments[j] }}>{parseInline(h)}</th>)}</tr></thead>
            <tbody>{dataRows.map((row, ri) => (
              <tr key={ri}>{row.map((cell, ci) => <td key={ci} style={{ textAlign: alignments[ci] || 'left' }}>{parseInline(cell)}</td>)}</tr>
            ))}</tbody>
          </table>
        </div>
      );
    }
    /* blockquote */
    else if (ln.startsWith('> ')) {
      const bqLines = [];
      while (i < lines.length && lines[i].startsWith('> ')) { bqLines.push(lines[i].slice(2)); i++; }
      els.push(<blockquote key={k++} className="md-bq">{bqLines.map((bl, j) => <p key={j}>{parseInline(bl)}</p>)}</blockquote>);
    }
    /* ordered list */
    else if (ln.match(/^\d+\.\s/)) {
      const items = [];
      while (i < lines.length && lines[i].match(/^\d+\.\s/)) { items.push(lines[i].replace(/^\d+\.\s/, '')); i++; }
      els.push(<ol key={k++}>{items.map((it, j) => <li key={j}>{parseInline(it)}</li>)}</ol>);
    }
    /* unordered list */
    else if (ln.match(/^[-*] /)) {
      const items = [];
      while (i < lines.length && lines[i].match(/^[-*] /)) { items.push(lines[i].replace(/^[-*] /, '')); i++; }
      els.push(<ul key={k++}>{items.map((it, j) => <li key={j}>{parseInline(it)}</li>)}</ul>);
    }
    else if (ln.trim() === '') { i++; }
    else { els.push(<p key={k++}>{parseInline(ln)}</p>); i++; }
  }
  return <div className="md-body">{els}</div>;
}

/* ─── Reusable Detail Components ──────────────────────────────────────────── */

function SectionHeader({ children, color }) {
  const c = color || T.cyan;
  return (
    <div style={{
      fontSize: 10, fontWeight: 700, textTransform: "uppercase",
      letterSpacing: ".14em", color: c, marginBottom: 16,
      fontFamily: "'Orbitron', sans-serif",
      textShadow: `0 0 6px ${c}44`,
      display: "flex", alignItems: "center", gap: 10,
    }}>
      <span style={{ width: 16, height: 1, background: c, boxShadow: `0 0 4px ${c}` }} />
      {children}
    </div>
  );
}

function StarRating({ rating, size = 14 }) {
  return (
    <span style={{ display: 'inline-flex', gap: 2 }}>
      {[1,2,3,4,5].map(s => (
        <span key={s} style={{
          fontSize: size,
          color: s <= Math.round(rating) ? T.yellow : T.textDim + '44',
          textShadow: s <= Math.round(rating) ? `0 0 6px ${T.yellow}66` : 'none',
        }}>★</span>
      ))}
    </span>
  );
}

/* ─── App Extended Content ─────────────────────────────────────────────────── */

const APP_FAQ = {
  _common: [
    { q: 'How do I install this app?', a: 'Click the **CONNECT** button in the header and enter your Melusina server URL. Then click the **INSTALL** button on the app detail page. The app will be deployed to your server automatically.' },
    { q: 'Is my data private?', a: 'Yes. All data stays on your Melusina server. There is no telemetry, analytics, or external data transmission. Each app Pearl is sandboxed and isolated.' },
    { q: 'How do I share access with others?', a: "Use Melusina's built-in sharing system. Click the sharing icon in your Pearl's top bar and generate a sharing link with the appropriate permission level (Viewer, Editor, or Admin)." },
    { q: 'How do I update to the latest version?', a: 'Updates appear automatically in your Melusina admin panel. You can also revisit the App Bazaar and re-install to get the latest version.' },
    { q: 'How do I backup my data?', a: "Use Melusina's built-in Pearl backup feature. Go to your Pearl's top-bar menu and select 'Download Backup'. This creates a portable .zip of your Pearl that can be restored on any Melusina server." },
    { q: 'Can I run multiple instances?', a: 'Yes. Each Melusina Pearl is an independent instance with its own data. You can create as many Pearls as you need.' },
  ],
  _openSource: [
    { q: 'Can I contribute to the source code?', a: 'Absolutely. Check the SOURCE link on the app page to find the GitHub repository. Pull requests and issues are welcome.' },
    { q: 'What license is this under?', a: 'This app is open source. Check the repository for the specific license file (commonly AGPLv3, MIT, or Apache 2.0).' },
  ],
  _sourceAvailable: [
    { q: 'What is the Melusina Public License (MPL-MEL)?', a: 'The Melusina Public License v3.0 (MPL-MEL-3.0) is a source-available license that lets you read, run, and deploy the software on your own server. Each version automatically converts to AGPLv3 open source five years after its own publish date.' },
    { q: 'Will this become open source?', a: "Yes. Under MPL-MEL-3.0, each released version automatically converts to AGPLv3 five years after that version's own publish date. You can view and audit the source code at any time." },
    { q: 'Can I modify the source code?', a: 'You have full access to the source for auditing and for deployment on your own server. Republishing, forking, or using AI or human effort to clone or compete with it is restricted until that version converts (the anti-clone terms).' },
  ],
};

/* ─── License Texts ─────────────────────────────────────────────────────────── */
const SOURCE_AVAILABLE_LICENSE_TEXT = `MELUSINA PUBLIC LICENSE v3.0 (MPL-MEL-3.0)
Source-available · AI-clone-protected · per-version AGPLv3 conversion

Copyright (c) 2026 Melusina Coop LU (Luxembourg) & Melusina Colorado LCA (USA),
joint 50/50 co-owners of the Melusina commons.

1. GRANT
This software is source-available. You may read, run, and — for security research — inspect the source we published, and deploy it on your own Melusina infrastructure for lawful internal or approved business use.

2. SOURCE AVAILABILITY
The source is published for inspection and audit. You may deploy and modify it for use on your own server.

3. RESTRICTIONS (before AGPLv3 conversion)
a) No use of AI systems or human effort to port, distill, retrain, or otherwise clone the software into an open, competing, or derivative product.
b) No republication, redistribution, or public forking of the source.
c) No sublicensing, and no claiming of platform, registry, or issuer authority.
d) Provenance, attribution, and license notices must be preserved.

4. AUTOMATIC OPEN-SOURCE CONVERSION
Every version converts to the GNU Affero General Public License version 3 (AGPLv3) automatically five (5) years after that version's own publish date, on a per-version clock.

5. DATA OWNERSHIP
All data created, stored, or processed by the Software on your infrastructure is owned entirely by you. The Software includes no telemetry, analytics, or data collection mechanisms. Your server, your data.

6. BRAND
The Melusina, NamedCoin, and pBay names and marks remain proprietary in perpetuity and never convert to AGPLv3.

7. WARRANTY DISCLAIMER
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY.

Full license: Melusina Public License v3.0 (MPL-MEL-3.0), DOC:M06.`;

const OPEN_SOURCE_LICENSE_TEXT = `GNU AFFERO GENERAL PUBLIC LICENSE
Version 3, 19 November 2007

Copyright (C) 2007 Free Software Foundation, Inc.

Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.

PREAMBLE
The GNU Affero General Public License is a free, copyleft license for software and other kinds of works, specifically designed to ensure cooperation with the community in the case of network server software.

The licenses for most software and other practical works are designed to take away your freedom to share and change the works. By contrast, our General Public Licenses are intended to guarantee your freedom to share and change all versions of a program — to make sure it remains free software for all its users.

TERMS AND CONDITIONS

0. Definitions.
"This License" refers to version 3 of the GNU Affero General Public License.
"The Program" refers to any copyrightable work licensed under this License.

1. Source Code.
You may copy and distribute verbatim copies of the Program's source code as you receive it, in any medium, provided that you conspicuously and appropriately publish on each copy an appropriate copyright notice and disclaimer of warranty.

2. Basic Permissions.
All rights granted under this License are granted for the term of copyright on the Program, and are irrevocable provided the stated conditions are met. This License explicitly affirms your unlimited permission to run the unmodified Program.

3. Protecting Users' Legal Rights From Anti-Circumvention Law.
No covered work shall be deemed part of an effective technological measure under any applicable law fulfilling obligations under article 11 of the WIPO copyright treaty.

4. Conveying Verbatim Copies.
You may convey verbatim copies of the Program's source code as you receive it, in any medium, provided that you conspicuously and appropriately publish on each copy an appropriate copyright notice.

13. Remote Network Interaction; Use with the GNU General Public License.
If you modify the Program, your modified version must prominently offer all users interacting with it remotely through a computer network an opportunity to receive the Corresponding Source of your version.

Full license text: https://www.gnu.org/licenses/agpl-3.0.en.html`;

/* ─── Sidecars & Grapple Connections ───────────────────────────────────────── */
//
// As of capabilities-v1: an app's `capabilities` object is an 8-axis profile
// per pearl: sidecars, grapple,
// encryption, roles, blockchains, staticPublishing, httpOut, incomingApi.
// The legacy {sidecars, grapple} shape used by badges + the existing
// SidecarsTab is derived by flattening the per-pearl profiles. New axes
// (encryption, roles, etc.) render as additional sections in PearlProfileTab.
// Turn one app's capability profile into the legacy {sidecars, grapple} shape the
// badges and SidecarsTab render. Returns null when the profile is absent or malformed.
function buildSidecarProfile(caps) {
  if (!caps || !Array.isArray(caps.pearls)) return null;
  {
    const grapple = [];
    const sidecars = [];
    for (const pearl of caps.pearls) {
      // Sidecars: collect required + stateless across pearls; dedupe by id+pearlId.
      for (const s of (pearl.sidecars || [])) {
        if (s.level === "none") continue;
        sidecars.push({
          required: s.level === "required",
          name: s.label || s.id,
          id: s.id,
          purpose: s.purpose || "",
          pearl: pearl.pearlName,
        });
      }
      // Grapple: offers → outgoing(?), requests → incoming. The legacy UI
      // labels "incoming" as down-arrow (consumed) and "outgoing" as up-arrow
      // (offered). Map: offers = OUT (this app exposes), requests = IN (this
      // app consumes from peers).
      for (const g of ((pearl.grapple && pearl.grapple.offers) || [])) {
        grapple.push({
          direction: "outgoing",
          capability: g.interface || g.name,
          apps: ["(any peer)"],
          purpose: g.purpose || "",
          type: "enhance",
          pearl: pearl.pearlName,
        });
      }
      for (const g of ((pearl.grapple && pearl.grapple.requests) || [])) {
        grapple.push({
          direction: "incoming",
          capability: g.interface || g.name,
          apps: ["(peer Pearl)"],
          purpose: g.purpose || "",
          type: g.required ? "dependency" : "enhance",
          pearl: pearl.pearlName,
        });
      }
    }
    return { sidecars, grapple, capabilities: caps };
  }
}

// Capabilities belong to the served, signed catalog row. A store-local profile
// map would be a second presentation authority that can outlive an app release,
// exactly the split that previously made the grid flash stale app data.
const LIVE_SIDECARS = {};
function registerLiveCapabilities(apps) {
  for (const app of apps || []) {
    const profile = buildSidecarProfile(app && app.capabilities);
    if (profile) LIVE_SIDECARS[app.appId] = profile;
  }
}

function getAppSidecars(appId) {
  return LIVE_SIDECARS[appId] ||
    { sidecars: [], grapple: [], capabilities: null };
}

function getConnectivityBadges(appId) {
  const sc = getAppSidecars(appId);
  const badges = [];
  if (sc.grapple.length > 0) {
    badges.push({
      icon: '\u{1FA9D}',
      short: 'Enhanced by Grapple',
      label: 'Enhanced by Grapple',
      tip: 'Can connect to other Pearls via Grapple for extra features',
      color: 'yellow',
    });
  }
  if (sc.sidecars.length > 0) {
    const hasRequired = sc.sidecars.some(s => s.required);
    if (hasRequired) {
      badges.push({
        icon: '\uD83C\uDFCD\uFE0F',
        short: 'Needs Sidecar',
        label: 'Needs Sidecar',
        tip: 'Requires server-level sidecar services to function',
        color: 'magenta',
      });
    }
  }
  return badges;
}

function getAppFAQ(app) {
  const specific = (APP_FAQ[app.appId] || []).map((item, i) => i === 0 ? { ...item, featured: true } : item);
  const license = (app.isOpenSource ? APP_FAQ._openSource : APP_FAQ._sourceAvailable).map((item, i) => i === 0 ? { ...item, featured: true } : item);
  const common = APP_FAQ._common.map((item, i) => i === 1 ? { ...item, featured: true } : item);
  return [...specific, ...license, ...common];
}

/* ─── Detail Page ──────────────────────────────────────────────────────────── */

function DetailPage({ app, onClose, onInstall, initialTab, initialDevSubTab }) {
  const faq = useMemo(() => getAppFAQ(app), [app]);
  const githubUrl = app.codeLink || '';

  const featuredFaqSet = useMemo(() => {
    const s = new Set();
    faq.forEach((item, i) => { if (item.featured) s.add(i); });
    return s;
  }, [faq]);

  const [tab, setTab] = useState(initialTab || 'overview');
  const [openFaq, setOpenFaq] = useState(() => new Set(featuredFaqSet));
  const [devSubTab, setDevSubTab] = useState(initialDevSubTab || 'suggestions');

  useEffect(() => {
    const h = (e) => e.key === "Escape" && onClose();
    window.scrollTo(0, 0);
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  useEffect(() => { setTab(initialTab || 'overview'); setOpenFaq(new Set(featuredFaqSet)); setDevSubTab(initialDevSubTab || 'suggestions'); }, [app.appId, featuredFaqSet, initialTab, initialDevSubTab]);

  if (!app) return null;

  const rows = [
    ["VERSION", app.version || "—"],
    ["BUILD", app.versionNumber ?? "—"],
    ["AUTHOR", <>
      {app.author?.name || "—"}
      {app.author?.githubUsername && (
        <a href={`https://github.com/${app.author.githubUsername}`} target="_blank"
          rel="noopener noreferrer" style={{ marginLeft: 8, fontSize: 11 }}>
          @{app.author.githubUsername}
        </a>
      )}
    </>],
    ["UPSTREAM", app.upstreamAuthor || "—"],
    ...(signedPromotionAt(app) == null ? [] : [["LAST PROMOTED", fmtDate(signedPromotionAt(app))]]),
    ["PKG_ID", <code key="p" style={{
      fontSize: 10, color: T.cyan + "88", wordBreak: "break-all",
      fontFamily: "'JetBrains Mono', monospace",
    }}>{app.packageId}</code>],
  ];

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'faq', label: `FAQ (${faq.length})` },
    { id: 'license', label: app.isOpenSource ? '📖 License' : '📜 License' },
  ];

  const renderBtnStyle = (base, hover) => ({
    style: {
      display: "inline-flex", alignItems: "center", gap: 6,
      padding: "8px 18px", borderRadius: 3,
      border: `1px solid ${base}33`, background: base + "08",
      color: base, fontSize: 12, fontWeight: 600,
      cursor: "pointer", transition: "all .2s",
      fontFamily: "'JetBrains Mono', monospace",
      letterSpacing: ".05em",
      textShadow: `0 0 6px ${base}44`,
    },
    onMouseEnter: (e) => { e.currentTarget.style.borderColor = base + "77"; e.currentTarget.style.boxShadow = `0 0 15px ${base}44`; },
    onMouseLeave: (e) => { e.currentTarget.style.borderColor = base + "33"; e.currentTarget.style.boxShadow = "none"; },
  });

  /* ---- OVERVIEW TAB ---- */
  const OverviewTab = () => (
    <>
      {/* ─── Capabilities Profile (single column, no inner tabs) ─── */}
      {(() => {
        const sc = getAppSidecars(app.appId);
        const caps = sc.capabilities;
        if (!caps || !Array.isArray(caps.pearls) || caps.pearls.length === 0) return null;

        const A = app.attest || {};
        const explorer = (addr) => `https://explorer.solana.com/address/${addr}?cluster=devnet`;

        // Aggregate axes across all pearls.
        const realSidecars = [];
        const authorityBits = [];
        let anyEncryption = false;
        let anyHttpOut = false;
        let anyApiCapnp = false;
        let anyApiHttp = false;
        let anyStaticPub = false;
        const grappleRequests = [];
        for (const p of caps.pearls) {
          for (const s of (p.sidecars || []))    realSidecars.push(s);
          for (const a of ((p.authority || {}).requires || [])) authorityBits.push(a);
          if (p.encryption && p.encryption.supported) anyEncryption = true;
          if (p.httpOut && p.httpOut.enabled)         anyHttpOut = true;
          if (p.apis && (p.apis.capnp || []).length)  anyApiCapnp = true;
          if (p.apis && (p.apis.http  || []).length)  anyApiHttp  = true;
          if (p.staticPublishing && p.staticPublishing.enabled) anyStaticPub = true;
          for (const r of ((p.grapple || {}).requests || [])) grappleRequests.push(r);
        }

        // Flatten capability surfaces to one row per offer/api.
        const capRows = [];
        const isMulti = caps.pearls.length > 1;
        for (const p of caps.pearls) {
          const tag = isMulti ? p.pearlName : null;
          for (const c of ((p.apis || {}).capnp || [])) capRows.push({ kind: 'capnp', tag, ...c });
          for (const h of ((p.apis || {}).http  || [])) capRows.push({ kind: 'http',  tag, ...h });
          for (const o of ((p.grapple || {}).offers || [])) capRows.push({
            kind: 'offer', tag, name: o.interface || o.name, purpose: o.purpose,
            roleGate: 'anyMember',
          });
        }

        const tierColors = {
          admin:          { fg: T.magenta, label: 'Admin tier' },
          regular:        { fg: T.cyan,    label: 'Regular tier' },
          visitor:        { fg: T.green,   label: 'Visitor tier' },
          infrastructure: { fg: T.yellow,  label: 'Infrastructure' },
        };
        const tier = tierColors[caps.tier] || tierColors.regular;

        const roleColor = (role) => role === 'adminOnly' ? T.magenta
          : role === 'organizationOnly' ? T.yellow
          : role === 'anonymous' ? T.green
          : T.cyan;
        const roleLabel = (role) => role === 'adminOnly' ? 'admin'
          : role === 'organizationOnly' ? 'org'
          : role === 'anonymous' ? 'public'
          : role === 'anyMember' ? 'member'
          : '';

        const Tile = ({ title, children }) => (
          <div style={{
            background: T.bg + 'cc', borderRadius: T.radiusSm,
            border: `1px solid ${T.border}`, padding: 12, minHeight: 96,
            display: 'flex', flexDirection: 'column',
          }}>
            <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: T.textDim, fontFamily: "'JetBrains Mono', monospace", marginBottom: 6 }}>{title}</div>
            <div style={{ fontSize: 12, color: T.textSec, lineHeight: 1.5, flex: 1 }}>{children}</div>
          </div>
        );
        const YesNo = ({ on, label }) => (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: on ? T.green : T.textDim, boxShadow: on ? `0 0 6px ${T.greenGlow}` : 'none' }} />
            <span style={{ color: on ? T.text : T.textDim }}>{label}</span>
          </div>
        );

        return (
          <div style={{ marginBottom: 28 }}>
            {/* hero row: tier + attestation chip */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
              <span style={{
                fontSize: 10, padding: '3px 10px', borderRadius: 3,
                border: `1px solid ${tier.fg}66`, color: tier.fg,
                fontFamily: "'JetBrains Mono', monospace",
                textTransform: 'uppercase', letterSpacing: '.08em', fontWeight: 700,
              }}>{tier.label}</span>
              {caps.pearls.map((p, i) => (
                <span key={i} style={{
                  fontSize: 10, padding: '3px 10px', borderRadius: 3,
                  border: `1px solid ${T.border}`, color: T.textSec,
                  fontFamily: "'JetBrains Mono', monospace",
                  textTransform: 'uppercase', letterSpacing: '.05em',
                }}>{p.pearlType.replace('-pearl','')}: {p.pearlName}</span>
              ))}
              {A.releaseEntryPda && (
                <a href={explorer(A.releaseEntryPda)} target="_blank" rel="noopener noreferrer" title={`Release seat ${A.releaseEntryPda}\nSigned ${A.signedAtUnix ? new Date(A.signedAtUnix*1000).toISOString().slice(0,19).replace('T',' ') + ' UTC' : '(no time)'}\nMaster NFT ${A.MasterNftMint || ''}`} style={{
                  fontSize: 10, padding: '3px 10px', borderRadius: 3,
                  border: `1px solid ${T.green}66`, color: T.green, background: T.green + '11',
                  fontFamily: "'JetBrains Mono', monospace", textDecoration: 'none',
                  letterSpacing: '.05em', display: 'inline-flex', alignItems: 'center', gap: 6,
                }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: T.green, boxShadow: `0 0 6px ${T.greenGlow}` }} />
                  on-chain · {A.releaseEntryPda.slice(0,4)}…{A.releaseEntryPda.slice(-4)}
                </a>
              )}
              {caps.pearls[0].hostShell && (
                <span style={{
                  fontSize: 10, padding: '3px 10px', borderRadius: 3,
                  border: `1px solid ${T.yellow}66`, color: T.yellow,
                  fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.05em',
                }}>hosted by {caps.pearls[0].hostShell.label}</span>
              )}
            </div>

            {/* Security & Authority strip — 4 tiles */}
            <SectionHeader color={T.cyan}>Security &amp; Authority</SectionHeader>
            <div style={{
              display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, marginBottom: 22,
            }}>
              <Tile title="Sidecars">
                {realSidecars.length === 0
                  ? <span style={{ color: T.textDim }}>None — pearl runs without external host services.</span>
                  : realSidecars.map((s, i) => (
                      <div key={i} style={{ marginBottom: 4 }}>
                        <code style={{ color: T.cyan, fontSize: 11 }}>{s.id}</code>
                        {s.purpose && <div style={{ fontSize: 11, color: T.textDim }}>{s.purpose}</div>}
                      </div>
                    ))
                }
              </Tile>
              <Tile title="Encryption">
                {anyEncryption ? (
                  <>
                    <div style={{ color: T.green, fontWeight: 700 }}>✓ at rest</div>
                    <div style={{ fontSize: 11, color: T.textDim, marginTop: 3 }}>
                      {(caps.pearls.find(p => p.encryption && p.encryption.supported) || {}).encryption?.scheme || ''}
                    </div>
                  </>
                ) : <span style={{ color: T.textDim }}>Not encrypted at rest — pearl holds no sensitive persistent state.</span>}
              </Tile>
              <Tile title="Authority required">
                {authorityBits.length === 0
                  ? <span style={{ color: T.textDim }}>None — no license-level permission bits required.</span>
                  : (
                    <>
                      <div style={{ color: T.magenta, fontWeight: 700, marginBottom: 4 }}>{authorityBits.length} bit{authorityBits.length > 1 ? 's' : ''}</div>
                      {authorityBits.slice(0, 3).map((a, i) => (
                        <div key={i} style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: T.textSec }}>{a.bit}</div>
                      ))}
                      {authorityBits.length > 3 && <div style={{ fontSize: 11, color: T.textDim }}>+ {authorityBits.length - 3} more</div>}
                    </>
                  )
                }
              </Tile>
              <Tile title="Network reach">
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
                  <YesNo on={anyApiCapnp}  label="Cap'n Proto in" />
                  <YesNo on={anyApiHttp}   label="HTTP in" />
                  <YesNo on={anyHttpOut}   label="HTTP out" />
                  <YesNo on={anyStaticPub} label="Static publish" />
                </div>
              </Tile>
            </div>

            {/* What it does — purpose paragraphs + flat capability list */}
            <SectionHeader color={T.cyan}>What it does</SectionHeader>
            {caps.pearls.map((p, i) => (
              <div key={i} style={{
                background: T.surface, borderRadius: T.radiusSm,
                padding: 14, marginBottom: 10, border: `1px solid ${T.border}`,
              }}>
                {isMulti && (
                  <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: T.textDim, fontFamily: "'JetBrains Mono', monospace", marginBottom: 6 }}>
                    {p.pearlName} · {p.pearlType}
                  </div>
                )}
                <div style={{ fontSize: 13, color: T.textSec, lineHeight: 1.65 }}>{p.purpose}</div>
              </div>
            ))}

            {capRows.length > 0 && (
              <>
                <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: T.textDim, fontFamily: "'JetBrains Mono', monospace", margin: '14px 0 8px' }}>
                  Capabilities ({capRows.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 22 }}>
                  {capRows.map((c, i) => {
                    const rc = roleColor(c.roleGate);
                    return (
                      <div key={i} style={{
                        display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap',
                        paddingLeft: 10, borderLeft: `2px solid ${rc}55`,
                      }}>
                        {c.tag && (
                          <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 2, border: `1px solid ${T.border}`, color: T.textDim, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase' }}>{c.tag}</span>
                        )}
                        <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 2, border: `1px solid ${rc}66`, color: rc, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase' }}>{c.kind}</span>
                        <code style={{ fontSize: 12, color: T.text, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>{c.name}</code>
                        {roleLabel(c.roleGate) && (
                          <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 2, border: `1px solid ${rc}66`, color: rc, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase' }}>{roleLabel(c.roleGate)}</span>
                        )}
                        {c.purpose && <span style={{ fontSize: 12, color: T.textSec, lineHeight: 1.5, flexBasis: '100%', marginTop: 2 }}>{c.purpose}</span>}
                      </div>
                    );
                  })}
                </div>
              </>
            )}

            {/* Connects to — grapple requests + companion apps */}
            {(grappleRequests.length > 0 || (caps.companionApps && caps.companionApps.length > 0)) && (
              <>
                <SectionHeader color={T.cyan}>Connects to</SectionHeader>
                <div style={{
                  display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 22,
                  fontSize: 12, color: T.textSec,
                }}>
                  {grappleRequests.map((r, i) => (
                    <span key={`r-${i}`} title={r.purpose} style={{
                      padding: '4px 10px', borderRadius: 3,
                      border: `1px solid ${r.required ? T.magenta + '66' : T.border}`,
                      color: r.required ? T.magenta : T.textSec,
                      fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                    }}>{r.required ? '◆ ' : '◇ '}{r.interface || r.name}</span>
                  ))}
                  {(caps.companionApps || []).map((aid, i) => (
                    <a key={`c-${i}`} href={`#/app/${aid}`} style={{
                      padding: '4px 10px', borderRadius: 3, color: T.cyan, textDecoration: 'none',
                      border: `1px solid ${T.cyan}33`, fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                    }}>{aid.slice(0,8)}…</a>
                  ))}
                </div>
                <div style={{ fontSize: 11, color: T.textDim, marginTop: -16, marginBottom: 22 }}>
                  ◆ blocking · ◇ optional
                </div>
              </>
            )}

            {/* Inside the pearl — single details, auditor-grade */}
            <details style={{
              background: T.surface, borderRadius: T.radiusSm,
              border: `1px solid ${T.border}`, padding: '12px 16px', marginBottom: 22,
            }}>
              <summary style={{ cursor: 'pointer', fontSize: 12, fontWeight: 700, letterSpacing: '.06em', textTransform: 'uppercase', color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>Inside the pearl — auditor detail</summary>
              <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 18 }}>
                {caps.pearls.map((p, pi) => (
                  <div key={pi}>
                    {isMulti && <div style={{ fontSize: 11, fontWeight: 700, color: T.text, marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>{p.pearlName}</div>}

                    {/* Roles per group */}
                    {['adminOnly','organizationOnly','anyMember'].map(grp => {
                      const items = ((p.roles || {})[grp]) || [];
                      if (!items.length) return null;
                      const c = roleColor(grp);
                      return (
                        <div key={grp} style={{ marginBottom: 10 }}>
                          <div style={{ fontSize: 10, color: c, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>{roleLabel(grp)} role · {items.length}</div>
                          <ul style={{ paddingLeft: 18, fontSize: 12, color: T.textSec, lineHeight: 1.6, margin: 0 }}>
                            {items.map((it, i) => <li key={i}><strong style={{ color: T.text }}>{it.name}</strong>{it.purpose ? ` — ${it.purpose}` : ''}</li>)}
                          </ul>
                        </div>
                      );
                    })}

                    {/* Authority bits with full purpose strings */}
                    {((p.authority || {}).requires || []).length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 10, color: T.magenta, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>Authority bits required</div>
                        <ul style={{ paddingLeft: 18, fontSize: 12, color: T.textSec, lineHeight: 1.6, margin: 0 }}>
                          {p.authority.requires.map((a, i) => (
                            <li key={i}><code style={{ color: T.magenta, fontSize: 11 }}>{a.bit}</code>{a.purpose ? ` — ${a.purpose}` : ''}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Blockchains — explorer-linked */}
                    {Array.isArray(p.blockchains) && p.blockchains.length > 0 && p.blockchains.map((b, bi) => {
                      const explorerBase = b.chain === 'solana' ? 'https://explorer.solana.com/address/' : null;
                      const cluster = b.chain === 'solana' && b.cluster && b.cluster !== 'mainnet' ? `?cluster=${b.cluster}` : '';
                      return (
                        <div key={bi} style={{ marginBottom: 10 }}>
                          <div style={{ fontSize: 11, color: T.cyan, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", marginBottom: 3 }}>{b.chain}{b.cluster ? ` · ${b.cluster}` : ''}</div>
                          {b.purpose && <div style={{ fontSize: 12, color: T.textSec, lineHeight: 1.6, marginBottom: 4 }}>{b.purpose}</div>}
                          {Array.isArray(b.programs) && (
                            <ul style={{ paddingLeft: 18, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: T.textDim, lineHeight: 1.6, margin: 0 }}>
                              {b.programs.map((pr, j) => {
                                const trunc = `${pr.id.slice(0,8)}…${pr.id.slice(-4)}`;
                                return (
                                  <li key={j}>{pr.label}: {explorerBase
                                    ? <a href={`${explorerBase}${pr.id}${cluster}`} target="_blank" rel="noopener noreferrer" title={pr.id} style={{ color: T.cyan, textDecoration: 'none', borderBottom: `1px dotted ${T.cyan}` }}>{trunc}</a>
                                    : <code title={pr.id}>{trunc}</code>}{Array.isArray(pr.calls) && pr.calls.length ? ` (${pr.calls.join(', ')})` : ''}</li>
                                );
                              })}
                            </ul>
                          )}
                        </div>
                      );
                    })}

                    {/* HTTP out endpoint patterns (full) */}
                    {p.httpOut && p.httpOut.enabled && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 10, color: T.yellow, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>HTTP out</div>
                        {p.httpOut.purpose && <div style={{ fontSize: 12, color: T.textSec, lineHeight: 1.5, marginBottom: 4 }}>{p.httpOut.purpose}</div>}
                        {Array.isArray(p.httpOut.endpoints) && p.httpOut.endpoints.length > 0 && (
                          <ul style={{ paddingLeft: 18, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: T.textDim, lineHeight: 1.6, margin: 0 }}>
                            {p.httpOut.endpoints.map((e, i) => <li key={i}>{e}</li>)}
                          </ul>
                        )}
                      </div>
                    )}

                    {/* Encryption fields full list */}
                    {p.encryption && p.encryption.supported && Array.isArray(p.encryption.fields) && p.encryption.fields.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 10, color: T.green, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>Encrypted fields</div>
                        <ul style={{ paddingLeft: 18, fontSize: 11, color: T.textSec, lineHeight: 1.6, margin: 0 }}>
                          {p.encryption.fields.map((f, i) => <li key={i}>{f}</li>)}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}

                {/* On-chain attestation — auditor-grade detail */}
                {A.releaseEntryPda && (
                  <div>
                    <div style={{ fontSize: 10, color: T.green, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 6 }}>On-chain attestation</div>
                    <div style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: T.textSec, lineHeight: 1.8 }}>
                      <div>seat: <a href={explorer(A.releaseEntryPda)} target="_blank" rel="noopener noreferrer" style={{ color: T.cyan }}>{A.releaseEntryPda}</a></div>
                      {A.appHash && <div>appHash: <code style={{ color: T.textDim }}>{A.appHash}</code></div>}
                      {A.releaseHash && <div>releaseHash: <code style={{ color: T.textDim }}>{A.releaseHash}</code></div>}
                      {A.MasterNftMint && <div>master NFT: <a href={explorer(A.MasterNftMint)} target="_blank" rel="noopener noreferrer" style={{ color: T.cyan }}>{A.MasterNftMint}</a></div>}
                      {A.licenseSquadsVault && <div>Squads vault: <a href={explorer(A.licenseSquadsVault)} target="_blank" rel="noopener noreferrer" style={{ color: T.cyan }}>{A.licenseSquadsVault}</a></div>}
                      {A.quorumPolicy && A.quorumPolicy.multisigPda && <div>multisig ({A.quorumPolicy.threshold || '?'}-of-{A.quorumPolicy.memberCount || '?'}): <a href={explorer(A.quorumPolicy.multisigPda)} target="_blank" rel="noopener noreferrer" style={{ color: T.cyan }}>{A.quorumPolicy.multisigPda}</a></div>}
                      {A.signedAtUnix && <div>signed: {new Date(A.signedAtUnix*1000).toISOString().replace('T',' ').slice(0,19)} UTC</div>}
                      {A.authorSig && <div style={{ wordBreak: 'break-all', color: T.textDim }}>sig: {A.authorSig}</div>}
                    </div>
                  </div>
                )}
              </div>
            </details>
          </div>
        );
      })()}

      <ScreenshotGallery screenshots={app.screenshots} appId={app.appId} />

      <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
        {app.description && (
          <div style={{
            padding: 24, background: T.surface,
            borderRadius: T.radius, border: `1px solid ${T.border}`,
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <SectionHeader>About</SectionHeader>
            {/* Version + updated prominently */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
              marginBottom: 16, padding: '10px 14px',
              background: T.cyan + '08', border: `1px solid ${T.cyan}22`,
              borderRadius: T.radiusSm,
            }}>
              <span style={{
                fontSize: 13, fontWeight: 700, color: T.cyan,
                fontFamily: "'Orbitron', sans-serif",
                textShadow: `0 0 6px ${T.accentGlow}`,
              }}>v{app.version || app.versionNumber || '\u2014'}</span>
              {app.versionNumber && app.version && (
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                  build {app.versionNumber}
                </span>
              )}
              {timeAgo(signedPromotionAt(app)) && (
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                  {'\u00b7'} updated {timeAgo(signedPromotionAt(app))}
                </span>
              )}
              {app.author?.name && (
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                  {'\u00b7'} by {app.author.name}
                </span>
              )}
            </div>
            <SimpleMarkdown text={app.description} />
          </div>
        )}
      </div>
    </>
  );

    /* ---- LICENSE TAB ---- */
  const LicenseTab = () => (
    <div style={{ maxWidth: 780 }}>
      <div style={{
        padding: 28, background: T.surface, borderRadius: T.radius,
        border: `1px solid ${app.isOpenSource ? T.green + '33' : T.magenta + '33'}`,
        marginBottom: 20,
        backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 18 }}>
          <span style={{
            fontSize: 24, width: 44, height: 44, borderRadius: 3,
            display: "flex", alignItems: "center", justifyContent: "center",
            background: app.isOpenSource ? T.green + '15' : T.magenta + '15',
            border: `1px solid ${app.isOpenSource ? T.green + '33' : T.magenta + '33'}`,
          }}>{app.isOpenSource ? '\ud83d\udd13' : '\ud83d\udd10'}</span>
          <div>
            <div style={{
              fontSize: 20, fontWeight: 800,
              color: app.isOpenSource ? T.green : T.magenta,
              fontFamily: "'Orbitron', sans-serif",
              textShadow: `0 0 8px ${app.isOpenSource ? T.greenGlow : T.magentaGlow}`,
            }}>{app.isOpenSource ? 'AGPLv3 License' : 'MPL-MEL License'}</div>
            <div style={{ fontSize: 12, color: T.textDim, marginTop: 4, fontFamily: "'JetBrains Mono', monospace" }}>
              Self-hosted · No subscription · Full data ownership
            </div>
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 13, color: T.textSec, marginBottom: 20 }}>
          {[
            '✓ Self-hosted on your server',
            '✓ No usage fees or limits',
            '✓ Full data ownership',
            app.isOpenSource ? '✓ Fork and modify freely' : '✓ Source-available for audit',
            app.isOpenSource ? '✓ Community contributions welcome' : '✓ Converts to AGPLv3 after 5 years',
          ].map((item, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: app.isOpenSource ? T.green : T.magenta, fontFamily: "'JetBrains Mono', monospace" }}>{item}</span>
            </div>
          ))}
        </div>
        {/* Scrollable license text */}
        <div style={{
          maxHeight: 400, overflowY: 'auto', padding: 20,
          background: T.bg + 'cc', borderRadius: T.radiusSm,
          border: `1px solid ${T.border}`,
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, lineHeight: 1.8, color: T.textSec,
          whiteSpace: 'pre-wrap', wordBreak: 'break-word',
        }}>
          {app.isOpenSource ? OPEN_SOURCE_LICENSE_TEXT : SOURCE_AVAILABLE_LICENSE_TEXT}
        </div>
      </div>

      {/* Technical details */}
      <div style={{
        padding: 24, background: T.surface, borderRadius: T.radius,
        border: `1px solid ${T.border}`,
        backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
      }}>
        <SectionHeader>Technical Details</SectionHeader>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
          {rows.map(([label, val], i) => (
            <div key={label} style={{
              display: "flex", justifyContent: "space-between", alignItems: "flex-start",
              gap: 12, padding: "10px 0",
              borderBottom: i < rows.length - 1 ? `1px solid ${T.borderLight}` : "none",
              fontSize: 13,
            }}>
              <span style={{
                color: T.textDim, flexShrink: 0,
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10, letterSpacing: ".08em",
              }}>{label}</span>
              <span style={{ textAlign: "right", wordBreak: "break-word", color: T.textSec }}>{val}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  /* ---- APP DEVELOPMENT TAB (suggestions + bugs, each with voting & comments) ---- */
  const VoteButton = ({ dir, active, count, onClick }) => (
    <button onClick={onClick} style={{
      background: active ? (dir === 1 ? T.green + '18' : T.magenta + '18') : 'transparent',
      border: `1px solid ${active ? (dir === 1 ? T.green + '55' : T.magenta + '55') : T.border}`,
      color: active ? (dir === 1 ? T.green : T.magenta) : T.textDim,
      borderRadius: 3, padding: '4px 10px', cursor: 'pointer',
      fontSize: 12, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
      display: 'inline-flex', alignItems: 'center', gap: 4,
      transition: 'all .2s',
      textShadow: active ? `0 0 6px ${dir === 1 ? T.greenGlow : T.magentaGlow}` : 'none',
    }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = (dir === 1 ? T.green : T.magenta) + '66'; }}
      onMouseLeave={(e) => { if (!active) e.currentTarget.style.borderColor = T.border; }}
    >{dir === 1 ? '▲' : '▼'}{count !== undefined ? ` ${count}` : ''}</button>
  );

  /* ---- FAQ TAB ---- */
  const toggleFaq = (i) => {
    setOpenFaq(prev => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i); else next.add(i);
      return next;
    });
  };

  const FAQTab = () => (
    <div style={{ maxWidth: 780 }}>
      <SectionHeader>Frequently Asked Questions</SectionHeader>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 16 }}>
        {faq.map((item, i) => {
          const isOpen = openFaq.has(i);
          return (
            <div key={i} style={{
              border: `1px solid ${isOpen ? T.cyan + '33' : T.border}`,
              borderRadius: T.radius, overflow: "hidden", transition: "border-color .2s",
            }}>
              <button onClick={() => toggleFaq(i)} style={{
                width: "100%", textAlign: "left",
                padding: "16px 20px", cursor: "pointer",
                display: "flex", justifyContent: "space-between", alignItems: "center",
                gap: 12, fontSize: 13, fontWeight: 600, color: isOpen ? T.cyan : T.text,
                background: T.surface, border: "none", transition: "all .2s",
                fontFamily: "inherit",
              }}>
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  {item.featured && <span style={{ fontSize: 8, color: T.yellow, textShadow: `0 0 4px ${T.yellow}66` }}>★</span>}
                  {item.q}
                </span>
                <span style={{
                  fontSize: 16, color: T.cyan, transition: "transform .2s",
                  transform: isOpen ? 'rotate(45deg)' : 'none',
                  flexShrink: 0, fontFamily: "'JetBrains Mono', monospace",
                  textShadow: `0 0 4px ${T.accentGlow}`,
                }}>+</span>
              </button>
              {isOpen && (
                <div style={{
                  padding: "0 20px 18px", fontSize: 13, lineHeight: 1.8, color: T.textSec,
                  background: T.surface, borderTop: `1px solid ${T.borderLight}`,
                  animation: "fadeIn .15s ease-out",
                }}>
                  <div style={{ paddingTop: 14 }}>
                    <SimpleMarkdown text={item.a} />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );

  return (
    <div style={{ minHeight: "100dvh", animation: "fadeIn .15s ease-out" }}>
      {/* top bar */}
      <div style={{
        position: "sticky", top: 0, zIndex: 200,
        background: "linear-gradient(135deg, rgba(17,14,36,0.92), rgba(30,20,58,0.88))",
        backdropFilter: "blur(24px) saturate(1.5)", WebkitBackdropFilter: "blur(24px) saturate(1.5)",
        borderBottom: `1px solid ${T.purple}20`,
        boxShadow: "0 4px 30px rgba(17,14,36,0.5), inset 0 -1px 0 rgba(192,132,252,0.08)",
      }}>
        <div style={{
          maxWidth: 1200, margin: "0 auto", padding: "12px 20px",
          display: "flex", alignItems: "center", gap: 14,
        }}>
          <button onClick={onClose} {...renderBtnStyle(T.cyan)}>← BACK</button>
          <span style={{
            fontSize: 14, fontWeight: 700, color: T.text,
            fontFamily: "'Orbitron', sans-serif",
            letterSpacing: ".03em",
          }}>{app.name}</span>
        </div>
      </div>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "32px 20px 120px" }}>
        {/* hero */}
        <div style={{ display: "flex", gap: 24, alignItems: "center", marginBottom: 28, flexWrap: "wrap" }}>
          <AppIcon app={app} size={160} />
          <div style={{ flex: 1, minWidth: 200 }}>
            <h1 style={{
              fontSize: 28, fontWeight: 800, margin: 0,
              fontFamily: "'Orbitron', sans-serif",
              letterSpacing: ".02em",
              background: `linear-gradient(135deg, ${T.cyan}, ${T.purple}, ${T.magenta})`,
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
              backgroundClip: "text",
              filter: `drop-shadow(0 0 12px ${T.purple}44)`,
            }}>
              {app.name}
            </h1>
            <p style={{ color: T.textSec, fontSize: 15, margin: "8px 0 0", lineHeight: 1.6 }}>
              {app.shortDescription || app.summary || ""}
            </p>
          </div>
        </div>

        {/* actions */}
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
          <button onClick={() => onInstall(app)} style={{
              display: "inline-flex", alignItems: "center", gap: 10,
              padding: "14px 36px", minHeight: 48,
              background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`,
              border: `1px solid ${T.cyan}66`,
              color: T.cyan,
              fontFamily: "'Orbitron', sans-serif",
              fontWeight: 700, fontSize: 13, letterSpacing: ".1em",
              textTransform: "uppercase",
              borderRadius: 3, cursor: "pointer",
              textShadow: `0 0 10px ${T.accentGlow}`,
              boxShadow: `0 0 20px ${T.accentGlow}, inset 0 0 20px ${T.cyan}08`,
              transition: "all .2s ease",
            }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = T.cyan + "33";
                e.currentTarget.style.boxShadow = `0 0 40px ${T.accentGlow}, inset 0 0 30px ${T.cyan}11`;
                e.currentTarget.style.transform = "scale(1.03)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`;
                e.currentTarget.style.boxShadow = `0 0 20px ${T.accentGlow}, inset 0 0 20px ${T.cyan}08`;
                e.currentTarget.style.transform = "none";
              }}
            ><span style={{ fontSize: 16 }}>↓</span> INSTALL</button>
          {app.webLink && (
            <a href={app.webLink} target="_blank" rel="noopener noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "14px 24px", background: T.surface,
              border: `1px solid ${T.border}`, color: T.textSec,
              fontWeight: 600, fontSize: 13, borderRadius: 3,
              textDecoration: "none", transition: "all .2s",
              fontFamily: "'JetBrains Mono', monospace",
            }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = T.magenta + "55";
                e.currentTarget.style.color = T.magenta;
                e.currentTarget.style.textShadow = `0 0 6px ${T.magentaGlow}`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = T.border;
                e.currentTarget.style.color = T.textSec;
                e.currentTarget.style.textShadow = "none";
              }}
            >WEBSITE ↗</a>
          )}
          {app.codeLink && (
            <a href={app.codeLink} target="_blank" rel="noopener noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "14px 24px", background: T.surface,
              border: `1px solid ${T.border}`, color: T.textSec,
              fontWeight: 600, fontSize: 13, borderRadius: 3,
              textDecoration: "none", transition: "all .2s",
              fontFamily: "'JetBrains Mono', monospace",
            }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = T.green + "55";
                e.currentTarget.style.color = T.green;
                e.currentTarget.style.textShadow = `0 0 6px ${T.greenGlow}`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = T.border;
                e.currentTarget.style.color = T.textSec;
                e.currentTarget.style.textShadow = "none";
              }}
            >SOURCE ↗</a>
          )}
          {githubUrl && (
            <a href={githubUrl + '#readme'} target="_blank" rel="noopener noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "14px 24px", background: T.surface,
              border: `1px solid ${T.border}`, color: T.textSec,
              fontWeight: 600, fontSize: 13, borderRadius: 3,
              textDecoration: "none", transition: "all .2s",
              fontFamily: "'JetBrains Mono', monospace",
            }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = T.purple + "55";
                e.currentTarget.style.color = T.purple;
                e.currentTarget.style.textShadow = `0 0 6px ${T.purple}44`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = T.border;
                e.currentTarget.style.color = T.textSec;
                e.currentTarget.style.textShadow = "none";
              }}
            >📖 README ↗</a>
          )}
        </div>

        {/* license row */}
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: 'center', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.06em', textTransform: 'uppercase' }}>License</span>
            <button onClick={() => setTab('license')} style={{
              background: 'none', border: 'none', padding: 0, cursor: 'pointer',
              fontSize: 14, fontWeight: 700,
              color: app.isOpenSource ? T.green : T.magenta,
              fontFamily: "'Orbitron', sans-serif",
              textShadow: `0 0 6px ${app.isOpenSource ? T.greenGlow : T.magentaGlow}`,
              textDecoration: 'underline', textUnderlineOffset: 3, textDecorationColor: 'currentcolor',
              transition: 'opacity .2s',
            }}
              onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.8'; }}
              onMouseLeave={(e) => { e.currentTarget.style.opacity = '1'; }}
            >{app.isOpenSource ? 'Open Source' : 'MPL-MEL'}</button>
          </div>
        </div>

        {/* tags */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          {(app.categories || []).map((c) => <Badge key={c}>{c}</Badge>)}
        </div>
        {/* connectivity badges */}
        {getConnectivityBadges(app.appId).length > 0 && (
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 24 }}>
            {getConnectivityBadges(app.appId).map((b, i) => (
              <div key={`conn-${i}`} style={{
                display: 'inline-flex', alignItems: 'center', gap: 10,
                padding: '8px 14px', borderRadius: 3,
                background: (b.color === 'yellow' ? T.yellow : T.magenta) + '08',
                border: `1px solid ${(b.color === 'yellow' ? T.yellow : T.magenta)}33`,
              }}>
                <span style={{ fontSize: 16, flexShrink: 0 }}>{b.icon}</span>
                <div>
                  <div style={{
                    fontSize: 11, fontWeight: 700,
                    color: b.color === 'yellow' ? T.yellow : T.magenta,
                    fontFamily: "'Orbitron', sans-serif",
                    letterSpacing: '.04em',
                  }}>{b.label}</div>
                  <div style={{ fontSize: 11, color: T.textDim, lineHeight: 1.4, marginTop: 2 }}>{b.tip}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* tab navigation */}
        <div className="detail-tabs">
          {tabs.map(t => (
            <button key={t.id} className={`detail-tab${tab === t.id ? ' active' : ''}`}
              onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>

        {/* tab content */}
        <div style={{ animation: "fadeIn .2s ease-out" }} key={tab}>
          {tab === 'overview' && <OverviewTab />}
          {tab === 'faq' && <FAQTab />}
          {tab === 'license' && <LicenseTab />}
        </div>
      </div>

      {/* sticky mobile install bar */}
      <div className="mobile-sticky-install" style={{
        position: "fixed", bottom: 0, left: 0, right: 0, zIndex: 300,
        background: "linear-gradient(135deg, rgba(17,14,36,0.96), rgba(30,20,58,0.94))",
        backdropFilter: "blur(20px) saturate(1.4)", WebkitBackdropFilter: "blur(20px) saturate(1.4)",
        borderTop: `1px solid ${T.purple}30`,
        boxShadow: `0 -4px 30px rgba(17,14,36,0.6)`,
        padding: "12px 20px",
        display: "none",
      }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: T.text, fontFamily: "'Orbitron', sans-serif", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{app.name}</div>
          </div>
          <button onClick={() => onInstall(app)} style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            padding: "12px 28px", minHeight: 48,
            background: `linear-gradient(135deg, ${T.cyan}33, ${T.magenta}22)`,
            border: `1px solid ${T.cyan}66`, color: T.cyan,
            fontFamily: "'Orbitron', sans-serif", fontWeight: 700, fontSize: 13,
            letterSpacing: ".1em", textTransform: "uppercase",
            borderRadius: 3, cursor: "pointer",
            textShadow: `0 0 10px ${T.accentGlow}`,
            boxShadow: `0 0 20px ${T.accentGlow}`,
          }}>↓ INSTALL</button>
        </div>
      </div>
    </div>
  );
}
/* ─── Main App ─────────────────────────────────────────────────────────────── */

function App() {
  const [apps, setApps] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const [installModalApp, setInstallModalApp] = useState(null);
  const [showGetMelusina, setShowGetMelusina] = useState(false);
  const [appNotFound, setAppNotFound] = useState(null);
  // "loading" until a served catalog answers; never a baked stand-in. The store used to
  // paint a catalog baked into this bundle at build time and then swap it for the live
  // one. That made every card wrong for the first paint: 11 baked apps were no longer
  // published at all, and 18 of the 20 rows that did survive carried a stale packageId,
  // so an INSTALL clicked during the flash targeted a package the catalog no longer
  // serves. The served catalog is now the only catalog.
  const [catalogState, setCatalogState] = useState("loading"); // loading | ready | error

  useEffect(() => {
    let cancelled = false;
    const normalize = (arr) => arr.map((a) => ({ ...a, categories: a.categories || [] }));
    // Both entries resolve to the same origin today (APP_INDEX_BASE is
    // window.location.origin), so this is one source, not a fallback pair. Kept as a
    // list so a real mirror can be added without restructuring the loader — but do not
    // read it as redundancy that exists.
    const sources = ["/apps/index.json", `${APP_INDEX_BASE}/apps/index.json`];
    (async () => {
      for (const url of sources) {
        try {
          const r = await fetch(url, { cache: "no-store" });
          if (!r.ok) continue;
          const j = await r.json();
          const src = Array.isArray(j) ? j : j.apps || [];
          if (src.length && !cancelled) { registerLiveCapabilities(src); setApps(normalize(src)); setCatalogState("ready"); return; }
        } catch { /* try next source */ }
      }
      // Every source failed. Say so plainly rather than showing a catalog we cannot
      // stand behind — a wrong install target is worse than a visible outage.
      if (!cancelled) setCatalogState("error");
    })();
    return () => { cancelled = true; };
  }, []);



  /* ─── ?host= URL parameter: register server on open ─── */
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const hostParam = params.get('host');
      if (!hostParam) return;
      const h = sanitizeHost(hostParam);
      if (!h) return;

      const pbayMatch = isPbayHost(h);
      if (pbayMatch) {
        setPbayServer(pbayMatch);
      } else {
        addPrivateServer(h);
      }

      // Clean the URL without reloading
      const url = new URL(window.location);
      url.searchParams.delete('host');
      window.history.replaceState({}, '', url.pathname + url.search + url.hash);
    } catch { /* in-app browsers may restrict URL APIs — fail silently */ }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /* ─── ?app=<appId> deep-link: open detail page on mount ─── */
  useEffect(() => {
    if (apps.length === 0) return;
    try {
      const params = new URLSearchParams(window.location.search);
      const appParam = params.get('app');
      if (!appParam) return;
      const match = apps.find((a) => a.appId === appParam);
      if (match) {
        setSelectedId(match.appId);
      } else {
        setAppNotFound(appParam);
        const url = new URL(window.location);
        url.searchParams.delete('app');
        window.history.replaceState({}, '', url.pathname + url.search + url.hash);
      }
    } catch { /* in-app browsers may restrict URL APIs — fail silently */ }
  }, [apps]);

  /* Sync ?app= to URL whenever selection changes (bookmarkable detail pages). */
  useEffect(() => {
    try {
      const url = new URL(window.location);
      if (selectedId) url.searchParams.set('app', selectedId);
      else url.searchParams.delete('app');
      window.history.replaceState({}, '', url.pathname + url.search + url.hash);
    } catch { /* fail silently in restricted browsers */ }
  }, [selectedId]);

  const onInstall = useCallback((app) => { setInstallModalApp(app); }, []);

  const categories = useMemo(() => {
    const s = new Set();
    apps.forEach((a) => a.categories.forEach((c) => s.add(c)));
    return ["All", ...Array.from(s).sort()];
  }, [apps]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return apps.filter((a) => {
      const catOk = category === "All" || a.categories.some((c) => c.toLowerCase() === category.toLowerCase());
      const qOk = !q || [a.name, a.shortDescription, a.summary, a.upstreamAuthor, a.author?.name]
        .filter(Boolean).some((f) => f.toLowerCase().includes(q));
      return catOk && qOk;
    });
  }, [apps, query, category]);

  const selectedApp = useMemo(() => apps.find((a) => a.appId === selectedId), [apps, selectedId]);
  const [detailInitTab, setDetailInitTab] = useState(null);
  const [detailInitSubTab, setDetailInitSubTab] = useState(null);
  const onSelect = useCallback((id, initTab, initSubTab) => {
    setDetailInitTab(initTab || null);
    setDetailInitSubTab(initSubTab || null);
    setSelectedId(id);
  }, []);
  const onClose = useCallback(() => { setSelectedId(null); setDetailInitTab(null); setDetailInitSubTab(null); }, []);
  if (selectedApp) {
    return (
      <>
        <style>{CSS}</style>
        <DetailPage app={selectedApp} onClose={onClose} onInstall={onInstall} initialTab={detailInitTab} initialDevSubTab={detailInitSubTab} />
        {installModalApp && <InstallModal app={installModalApp} onClose={() => setInstallModalApp(null)} />}
        {showGetMelusina && <GetMelusinaModal onClose={() => setShowGetMelusina(false)} />}
      </>
    );
  }

  return (
    <>
      <style>{CSS}</style>

      {/* header */}
      <header style={{
        position: "sticky", top: 0, zIndex: 200,
        background: "linear-gradient(135deg, rgba(17,14,36,0.92), rgba(30,20,58,0.88))",
        backdropFilter: "blur(24px) saturate(1.5)",
        WebkitBackdropFilter: "blur(24px) saturate(1.5)",
        borderBottom: `1px solid ${T.purple}20`,
        boxShadow: "0 4px 30px rgba(17,14,36,0.5), inset 0 -1px 0 rgba(192,132,252,0.08)",
      }}>
        <div style={{
          maxWidth: 1440, margin: "0 auto", padding: "12px 24px",
          display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
        }}>
          {/* Logo */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: "auto" }}>
            <img src={LOGO_URL} alt="Melusina" style={{
              width: 36, height: 36, borderRadius: 3,
              filter: `drop-shadow(0 0 8px ${T.cyan}88) drop-shadow(0 0 20px ${T.accentGlow})`,
              animation: "flicker 4s ease-in-out infinite",
            }} />
            <h1 style={{
              fontSize: 16, fontWeight: 800, letterSpacing: ".05em",
              fontFamily: "'Orbitron', sans-serif",
              margin: 0, lineHeight: 1,
            }}>
              <span className="neon-text" style={{ animation: "flicker 4s ease-in-out infinite" }}>
                MELUSINA
              </span>
              <span style={{
                color: T.textDim, fontWeight: 400, marginLeft: 8, fontSize: 11,
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: ".12em", textTransform: "uppercase",
              }}>
                APP BAZAAR
              </span>
            </h1>
            {/* Get Melusina CTA */}
            <button onClick={() => setShowGetMelusina(true)} style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '8px 16px', borderRadius: 3,
              background: `linear-gradient(135deg, ${T.green}18, ${T.cyan}12)`,
              border: `1px solid ${T.green}55`,
              color: T.green, fontSize: 10, fontWeight: 700,
              fontFamily: "'Orbitron', sans-serif", letterSpacing: '.06em',
              cursor: 'pointer', transition: 'all .2s', whiteSpace: 'nowrap',
              textShadow: `0 0 6px ${T.greenGlow}`,
            }}
              onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 15px ${T.greenGlow}`; e.currentTarget.style.borderColor = T.green + '88'; }}
              onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = T.green + '55'; }}
            >GET MELUSINA</button>
          </div>

          {/* Search */}
          <div style={{ position: "relative", flex: "1 1 160px", maxWidth: 320 }}>
            <span style={{
              position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)",
              fontSize: 13, color: T.cyan + "66", pointerEvents: "none",
              fontFamily: "'JetBrains Mono', monospace",
            }}>⌕</span>
            <input type="search" placeholder="search_apps..." value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{
                width: "100%", padding: "10px 14px 10px 34px",
                background: "rgba(192,132,252,0.06)",
                border: `1px solid ${T.purple}22`, borderRadius: T.radiusSm, color: T.text,
                fontSize: 13, outline: "none", transition: "all .2s",
                fontFamily: "'JetBrains Mono', monospace",
              }}
              onFocus={(e) => {
                e.target.style.borderColor = T.cyan + "66";
                e.target.style.boxShadow = `0 0 15px ${T.accentGlow}`;
              }}
              onBlur={(e) => {
                e.target.style.borderColor = T.cyan + "22";
                e.target.style.boxShadow = "none";
              }}
            />
          </div>
        </div>
      </header>

      {/* categories */}
      <div style={{ maxWidth: 1440, margin: "0 auto", padding: "18px 24px 0" }}>
        <div className="cat-scroll" style={{
          display: "flex", gap: 8, overflowX: "auto", paddingBottom: 6,
          WebkitOverflowScrolling: "touch",
        }}>
          {categories.map((c) => {
            const active = category === c;
            return (
              <button key={c} onClick={() => setCategory(c)} style={{
                padding: "8px 20px", borderRadius: T.radiusSm,
                border: `1px solid ${active ? T.cyan + "55" : T.purple + "18"}`,
                background: active
                  ? `linear-gradient(135deg, ${T.cyan}18, ${T.purple}15)`
                  : "rgba(192,132,252,0.04)",
                color: active ? T.cyan : T.textSec,
                fontSize: 11, fontWeight: 600, cursor: "pointer",
                whiteSpace: "nowrap", transition: "all .25s", flexShrink: 0,
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: ".06em", textTransform: "uppercase",
                boxShadow: active ? `0 0 15px ${T.accentGlow}` : "none",
                textShadow: active ? `0 0 8px ${T.accentGlow}` : "none",
              }}>{c}</button>
            );
          })}
        </div>
      </div>

      {/* grid */}
      <main style={{ maxWidth: 1440, margin: "0 auto", padding: "20px 24px 80px" }}>
        {appNotFound && (
          <div role="status" style={{
            margin: "0 0 16px", padding: "12px 16px",
            background: T.yellow + '12',
            border: `1px solid ${T.yellow}55`,
            borderRadius: T.radiusSm,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 12, color: T.yellow,
          }}>
            <span>App <code style={{ color: T.text }}>{appNotFound}</code> is not in this catalog. Showing all apps.</span>
            <button onClick={() => setAppNotFound(null)} aria-label="Dismiss" style={{
              background: 'none', border: 'none', color: T.yellow, fontSize: 16,
              cursor: 'pointer', padding: '0 4px', lineHeight: 1,
            }}>×</button>
          </div>
        )}
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20
        }}>
          <span style={{
            fontSize: 11, color: T.textDim,
            fontFamily: "'JetBrains Mono', monospace",
            letterSpacing: ".06em",
          }}>
            {catalogState === "ready" ? (
              <>
                <span style={{ color: T.cyan + "aa" }}>{filtered.length}</span>
                {" "}app{filtered.length !== 1 ? "s" : ""}
                {category !== "All" && <> in <span style={{ color: T.magenta + "aa" }}>{category}</span></>}
              </>
            ) : catalogState === "loading" ? (
              <span style={{ color: T.cyan + "aa" }}>loading catalog…</span>
            ) : (
              <span style={{ color: T.magenta + "aa" }}>catalog unavailable</span>
            )}
          </span>
        </div>

        {catalogState === "loading" ? (
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 310px), 1fr))",
            gap: 16,
          }} aria-busy="true" aria-label="Loading catalog">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="app-card-skeleton" style={{
                height: 208, borderRadius: 3,
                border: `1px solid ${T.cyan}22`,
                background: `linear-gradient(135deg, ${T.cyan}0c, ${T.magenta}08)`,
                animationDelay: `${i * 80}ms`,
              }} />
            ))}
          </div>
        ) : catalogState === "error" ? (
          <div style={{ textAlign: "center", padding: "80px 20px", color: T.textDim }}>
            <div style={{
              fontSize: 56, marginBottom: 16, opacity: .35, color: T.magenta,
              textShadow: `0 0 20px ${T.magenta}55`,
              fontFamily: "'Orbitron', sans-serif",
            }}>⚠</div>
            <p style={{
              fontSize: 14, fontWeight: 700, color: T.textSec,
              fontFamily: "'Orbitron', sans-serif", letterSpacing: ".1em",
            }}>CATALOG UNAVAILABLE</p>
            <p style={{
              fontSize: 12, marginTop: 8, color: T.textDim,
              fontFamily: "'JetBrains Mono', monospace",
            }}>the served app catalog could not be reached — reload to retry</p>
          </div>
        ) : filtered.length > 0 ? (
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 310px), 1fr))",
            gap: 16,
          }}>
            {filtered.map((app, i) => (
              <div key={app.appId} style={{ animationDelay: `${i * 60}ms` }}>
                <AppCard app={app} onSelect={onSelect} onInstall={onInstall} />
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: "80px 20px", color: T.textDim }}>
            <div style={{
              fontSize: 56, marginBottom: 16, opacity: .3,
              color: T.cyan,
              textShadow: `0 0 20px ${T.accentGlow}`,
              fontFamily: "'Orbitron', sans-serif",
            }}>∅</div>
            <p style={{
              fontSize: 14, fontWeight: 700, color: T.textSec,
              fontFamily: "'Orbitron', sans-serif",
              letterSpacing: ".1em",
            }}>NO RESULTS</p>
            <p style={{
              fontSize: 12, marginTop: 8, color: T.textDim,
              fontFamily: "'JetBrains Mono', monospace",
            }}>try a different search or category</p>
          </div>
        )}
      </main>

      {/* bottom sunset glow */}
      <div style={{
        position: "fixed", bottom: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, transparent, ${T.peach}44, ${T.magenta}55, ${T.purple}44, ${T.cyan}33, transparent)`,
        pointerEvents: "none",
        boxShadow: `0 0 20px ${T.magenta}22, 0 0 40px ${T.purple}11`,
      }} />
      {installModalApp && <InstallModal app={installModalApp} onClose={() => setInstallModalApp(null)} />}
      {showGetMelusina && <GetMelusinaModal onClose={() => setShowGetMelusina(false)} />}
    </>
  );
}

class RootErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error) {
    return { error };
  }
  componentDidCatch(error, info) {
    if (typeof console !== 'undefined') console.error('[bazaar] render error:', error, info);
  }
  render() {
    if (this.state.error) {
      return (
        <div style={{
          minHeight: '100dvh',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'linear-gradient(170deg, #0e0b1f 0%, #1a1040 50%, #110e24 100%)',
          padding: '24px',
        }}>
          <div role="alert" style={{
            maxWidth: 560, width: '100%',
            background: 'rgba(22,16,48,0.9)',
            border: `1px solid ${T.magenta}55`,
            borderRadius: T.radius,
            padding: '32px 28px',
            boxShadow: `0 0 40px ${T.magentaGlow}`,
            color: T.text,
            fontFamily: "'Inter', sans-serif",
          }}>
            <h1 style={{
              fontSize: 18, fontWeight: 800, color: T.magenta,
              fontFamily: "'Orbitron', sans-serif",
              textShadow: `0 0 8px ${T.magentaGlow}`,
              marginTop: 0, marginBottom: 12, letterSpacing: '.04em',
            }}>The bazaar hit a snag</h1>
            <p style={{ fontSize: 14, color: T.textSec, lineHeight: 1.7, marginBottom: 16 }}>
              The page failed to render. This is usually a transient browser issue — reloading clears it.
              If it persists, your browser may be missing a feature this site relies on.
            </p>
            <pre style={{
              fontSize: 11, color: T.textDim,
              background: 'rgba(0,0,0,0.25)',
              padding: '10px 12px', borderRadius: T.radiusSm,
              border: `1px solid ${T.border}`,
              fontFamily: "'JetBrains Mono', monospace",
              overflow: 'auto', maxHeight: 140,
              marginBottom: 18, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            }}>{String(this.state.error && (this.state.error.message || this.state.error))}</pre>
            <button onClick={() => window.location.reload()} style={{
              padding: '12px 22px', borderRadius: T.radiusSm,
              background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}15)`,
              border: `1px solid ${T.cyan}55`,
              color: T.cyan, fontSize: 12, fontWeight: 700,
              fontFamily: "'Orbitron', sans-serif",
              letterSpacing: '.08em', textTransform: 'uppercase',
              cursor: 'pointer', textShadow: `0 0 8px ${T.accentGlow}`,
            }}>Reload page</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById("root")).render(
  <RootErrorBoundary><App /></RootErrorBoundary>
);
