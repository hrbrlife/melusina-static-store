import React, { useEffect, useMemo, useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { format, formatDistanceToNow } from "date-fns";
import data from "./apps.json";

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

const APP_INDEX_BASE = "https://hrbrlife.github.io/melusina-static-store";
const LOGO_URL = `${APP_INDEX_BASE}/icons/melulogo-cyan.svg`;

/* ─── helpers ──────────────────────────────────────────────────────────────── */

const sanitizeHost = (h) => {
  if (!h) return "";
  const t = h.trim();
  return (!/^https?:\/\//i.test(t) ? `https://${t}` : t).replace(/\/+$/, "");
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

const latestVersionDate = (appId) => {
  const versions = APP_VERSIONS[appId];
  if (!versions || !versions.length) return null;
  return Date.parse(versions[0].date);
};

const imgUrl = (id) => (id ? `${APP_INDEX_BASE}/images/${id}` : null);

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
    if (!raw) {
      // migrate legacy single-server key
      const legacy = localStorage.getItem('melusina_pbay_server');
      if (legacy) {
        const srv = JSON.parse(legacy);
        if (srv && srv.code) { localStorage.setItem(PBAY_KEY, JSON.stringify([srv])); localStorage.removeItem('melusina_pbay_server'); return [srv]; }
      }
      return [];
    }
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
// legacy compat
const getPbayServer = () => { const list = getPbayServers(); return list.length > 0 ? list[0] : null; };
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
            <a href="https://pbay.app" target="_blank" rel="noreferrer" style={{
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
            <a href="https://melusina-os.org/install" target="_blank" rel="noreferrer" style={{
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

  const doInstall = useCallback((host) => {
    const h = sanitizeHost(host);
    if (!h) {
      window.alert("Enter a Melusina server URL before installing.");
      return;
    }
    if (!app.packageId) {
      window.alert(`Cannot install "${app.name || 'this app'}": package is missing from the catalog.`);
      return;
    }
    const pkg = app.packageUrl || `${APP_INDEX_BASE}/packages/${app.packageId}`;
    window.open(`${h}/install/${app.packageId}?url=${encodeURIComponent(pkg)}`, '_blank');
    onClose();
  }, [app, onClose]);

  const selectPbay = useCallback((srv) => {
    addPbayServer(srv);
    setPbayServersState(getPbayServers());
    setShowJurisdiction(false);
    doInstall(`https://${srv.domain}`);
  }, [doInstall]);

  const addAndInstallPrivate = useCallback(() => {
    const h = sanitizeHost(newPrivate);
    if (!h) return;
    addPrivateServer(h);
    setPrivateServers(getPrivateServers());
    setNewPrivate('');
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
          <button style={sectionTabStyle(section === 'pbay')} onClick={() => setSection('pbay')}>
            🌐 pbay.app
          </button>
          <button style={sectionTabStyle(section === 'private')} onClick={() => setSection('private')}>
            🖥️ Private Servers
          </button>
        </div>

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
                <input type="url" placeholder="https://sandstorm.example.com" value={newPrivate}
                  onChange={(e) => setNewPrivate(e.target.value)} autoFocus
                  onKeyDown={(e) => e.key === 'Enter' && addAndInstallPrivate()}
                  style={{
                    width: '100%', padding: '12px 14px',
                    background: 'rgba(192,132,252,0.06)',
                    border: `1px solid ${T.purple}33`,
                    borderRadius: T.radiusSm, color: T.text,
                    fontSize: 13, outline: 'none',
                    fontFamily: "'JetBrains Mono', monospace",
                    transition: 'border-color .2s, box-shadow .2s',
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = T.cyan + '88';
                    e.target.style.boxShadow = `0 0 15px ${T.accentGlow}`;
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = T.purple + '33';
                    e.target.style.boxShadow = 'none';
                  }}
                />
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

/* Community surfaces (reviews / feature wishes / bug reports / app ideas / comments)
 * were removed: they were localStorage-only, so they looked like public marketplace
 * submissions but never left the device. A polished bazaar doesn't ship fictional
 * community signals. These stubs return empty data so legacy call-sites don't crash;
 * the tabs and Ideas page that consumed them have been removed.
 */
const getUserReviews   = () => [];
const addUserReview    = () => [];
const getFeatureWishes = () => [];
const addFeatureWish   = () => [];
const voteFeatureWish  = () => ({ wishes: [], votes: {} });
const getMyFWVotes     = () => ({});
const getComments      = () => [];
const addComment       = () => [];
const getBugReports    = () => [];
const addBugReport     = () => [];
const voteBugReport    = () => ({ bugs: [], votes: {} });
const getMyBugVotes    = () => ({});
const getAppIdeas      = () => [];
const addAppIdea       = () => [];
const voteAppIdea      = () => ({ ideas: [], votes: {} });
const getMyAIVotes     = () => ({});

/* ─── palm beach sunset tokens ────────────────────────────────────────────── */

const T = {
  bg: "#110e24",
  bgAlt: "#1a1535",
  surface: "rgba(24, 18, 52, 0.72)",
  card: "rgba(28, 22, 58, 0.55)",
  cardHover: "rgba(42, 32, 78, 0.7)",
  border: "rgba(192, 132, 252, 0.1)",
  borderHover: "rgba(0, 229, 255, 0.35)",
  borderLight: "rgba(192, 132, 252, 0.06)",
  cyan: "#00e5ff",
  magenta: "#ff7eb3",
  green: "#4ade80",
  purple: "#c084fc",
  yellow: "#ffd166",
  coral: "#ff7eb3",
  peach: "#ffb86c",
  accent: "#00e5ff",
  accentHover: "#33ebff",
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

.detail-grid{display:grid;grid-template-columns:1fr 340px;gap:28px;align-items:start}
@media(max-width:900px){.detail-grid{grid-template-columns:1fr}}
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

.doc-layout{display:flex;gap:24px;align-items:flex-start}
.doc-sidebar{position:sticky;top:80px;min-width:180px;flex-shrink:0;display:flex;flex-direction:column;gap:4px}
@media(max-width:720px){.doc-layout{flex-direction:column}.doc-sidebar{position:static;flex-direction:row;overflow-x:auto;min-width:0;padding-bottom:4px}.doc-sidebar::-webkit-scrollbar{display:none}}
.fee-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:600px){.fee-grid-2{grid-template-columns:1fr}}

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

.review-card{padding:20px;background:${T.surface};border:1px solid ${T.border};border-radius:${T.radius}px;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);transition:border-color .2s}
.review-card:hover{border-color:${T.cyan}33}

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
  const [err, setErr] = useState(false);
  const src = imgUrl(app.imageId);
  if (!src || err) {
    const letter = (app.name || "?")[0].toUpperCase();
    return (
      <div style={{
        width: size, height: size, borderRadius: T.radiusSm,
        background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`,
        border: `1px solid ${T.cyan}44`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: size * .42, fontWeight: 700,
        fontFamily: "'Orbitron', sans-serif",
        color: T.cyan, flexShrink: 0,
        textShadow: `0 0 10px ${T.cyan}66`,
        boxShadow: `0 0 15px ${T.accentGlow}`,
      }}>
        {letter}
      </div>
    );
  }
  return (
    <img src={src} alt="" loading="lazy" onError={() => setErr(true)}
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

function AppCard({ app, onSelect, onInstall, onVersionClick }) {
  const [hov, setHov] = useState(false);
  const shots = (app.screenshots || []).slice(0, 5);
  const updatedAgo = timeAgo(latestVersionDate(app.appId) || app.createdAt);

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
          <div
            role="button" tabIndex={0}
            onClick={(e) => { e.stopPropagation(); onVersionClick && onVersionClick(app.appId); }}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); onVersionClick && onVersionClick(app.appId); } }}
            style={{
              fontSize: 11, color: T.textDim, marginTop: 3,
              fontFamily: "'JetBrains Mono', monospace",
              cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
              transition: 'color .2s',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = T.cyan; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = T.textDim; }}
          >
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
          {/* USP selling points */}
          {(APP_USP[app.appId] || []).length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6 }}>
              {(APP_USP[app.appId] || []).map((usp, ui) => (
                <div key={ui} style={{
                  display: 'flex', alignItems: 'flex-start', gap: 6,
                  fontSize: 12, lineHeight: 1.5, color: T.textSec,
                }}>
                  <span style={{ color: T.green, flexShrink: 0, fontSize: 13, textShadow: `0 0 4px ${T.greenGlow}` }}>✓</span>
                  <span>{usp}</span>
                </div>
              ))}
            </div>
          )}
          {/* Price display */}
          {(() => {
            const pr = getAppPrice(app.appId);
            const isFree = pr.price === 'FREE';
            const isZeroSol = !isFree && pr.price.match(/^0(\.0*)?\s*SOL$/);
            const priceColor = (isFree || isZeroSol) ? T.green : T.cyan;
            const priceGlow = (isFree || isZeroSol) ? T.greenGlow : T.accentGlow;
            const usd = solToUsd(pr.price);
            const origUsd = solToUsd(pr.originalPrice || '');
            return (
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                <span style={{
                  fontSize: 18, fontWeight: 800, color: priceColor,
                  fontFamily: "'Orbitron', sans-serif",
                  textShadow: `0 0 8px ${priceGlow}`,
                }}>{pr.price}</span>
                {usd && <span style={{ fontSize: 10, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{usd}</span>}
                {pr.onSale && pr.originalPrice && (
                  <span style={{ display: 'inline-flex', alignItems: 'baseline', gap: 4 }}>
                    <span style={{
                      fontSize: 12, color: T.textDim, textDecoration: 'line-through',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>{pr.originalPrice}</span>
                    {origUsd && <span style={{ fontSize: 9, color: T.textDim + '99', textDecoration: 'line-through', fontFamily: "'JetBrains Mono', monospace" }}>{origUsd}</span>}
                  </span>
                )}
              </div>
            );
          })()}
        </div>

        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          gap: 8, marginTop: "auto",
        }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", minWidth: 0 }}>
            {(app.categories || []).slice(0, 2).map((c) => <Badge key={c}>{c}</Badge>)}
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
  if (!screenshots || screenshots.length === 0) return null;

  const prev = () => setLightbox((i) => (i > 0 ? i - 1 : screenshots.length - 1));
  const next = () => setLightbox((i) => (i < screenshots.length - 1 ? i + 1 : 0));

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
        <div className="lightbox-overlay" onClick={() => setLightbox(null)}>
          {screenshots.length > 1 && (
            <button onClick={(e) => { e.stopPropagation(); prev(); }} style={{
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
            <img src={screenshotUrl(appId, screenshots[lightbox])} alt="" onClick={(e) => e.stopPropagation()} style={{ cursor: "default" }} />
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
            <button onClick={(e) => { e.stopPropagation(); next(); }} style={{
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
        parts.push(<a key={k++} href={m[2]} target="_blank" rel="noreferrer">{m[1]}</a>);
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

const APP_GITHUB = {};

/* ─── USP selling points per app (green checks) ───────────────────────────── */
const APP_USP = {};

/* legacy — docs removed, replaced with GitHub links */
const APP_DOCS = {};

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
  _hlsl: [
    { q: 'What is the HLSL license?', a: 'HLSL (Harbor Life Software License) is a source-available license that allows you to use and deploy the software on your own server. After 3 years, the code automatically converts to AGPLv3 open source.' },
    { q: 'Will this become open source?', a: 'Yes. Under the HLSL license, all code automatically converts to AGPLv3 after 3 years from the release date. You can view and audit the source code at any time.' },
    { q: 'Can I modify the source code?', a: 'You have full access to the source code for auditing. Modifications for personal use on your own server are permitted. Redistribution requires the HLSL terms.' },
  ],
};

const APP_REVIEWS = {};

const APP_VERSIONS = {};

/* ─── App Audits ────────────────────────────────────────────────────────────── */
const AUDIT_CATEGORIES = [
  { key: 'security', label: 'Security', icon: '🛡️' },
  { key: 'privacy', label: 'Privacy', icon: '🔒' },
  { key: 'dataSafety', label: 'Data Safety', icon: '💾' },
  { key: 'dataPortability', label: 'Data Portability', icon: '📦' },
  { key: 'codeQuality', label: 'Code Quality', icon: '⚙️' },
  { key: 'accessibility', label: 'Accessibility', icon: '♿' },
];

const APP_AUDITS = {};

/* ─── License Texts ─────────────────────────────────────────────────────────── */
const HLSL_LICENSE_TEXT = `HARBOR LIFE SOFTWARE LICENSE (HLSL) v1.0

Copyright (c) 2025 Harbor Life / hrbrlife

1. GRANT OF LICENSE
Permission is hereby granted to any person obtaining a copy of this software and associated documentation files (the "Software") to use, copy, and deploy the Software on their own self-hosted infrastructure (including Sandstorm, Melusina, or compatible platforms) for personal, educational, or internal business purposes.

2. SOURCE AVAILABILITY
The source code of the Software is made available for inspection, auditing, and personal modification. You may modify the Software for use on your own server. Redistribution of modified versions requires compliance with this license.

3. RESTRICTIONS
a) The Software may not be redistributed, sublicensed, or sold as a standalone product without prior written permission from the copyright holder.
b) The Software may not be used to provide a competing hosted service without a separate commercial agreement.
c) Attribution to the original author must be preserved in all copies and derivative works.

4. AUTOMATIC OPEN SOURCE CONVERSION
Three (3) years after the initial public release date of each version, the license for that version automatically and irrevocably converts to the GNU Affero General Public License version 3 (AGPLv3). The conversion date for each version is calculated from its first public distribution date.

5. DATA OWNERSHIP
All data created, stored, or processed by the Software on your infrastructure is owned entirely by you. The Software includes no telemetry, analytics, or data collection mechanisms. Your server, your data.

6. WARRANTY DISCLAIMER
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY.

7. TERMINATION
This license is effective until terminated. It will terminate automatically if you fail to comply with any term. Upon termination, you must destroy all copies of the Software.`;

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

const APP_FEES = { _platform: [] };

/* ─── App Prices ───────────────────────────────────────────────────────────── */
const APP_PRICES = {};

function getAppPrice(appId) {
  return APP_PRICES[appId] || { price: 'FREE' };
}

/* ─── Sidecars & Grapple Connections ───────────────────────────────────────── */
const APP_SIDECARS = {};

function getAppSidecars(appId) {
  return APP_SIDECARS[appId] || { sidecars: [], grapple: [] };
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

/* approximate SOL → USD (rough estimate; update as needed) */
const SOL_USD_RATE = 145;
function solToUsd(solStr) {
  const m = solStr.match(/([\d.]+)\s*SOL/);
  if (!m) return null;
  const usd = parseFloat(m[1]) * SOL_USD_RATE;
  if (usd === 0) return null;
  return `≈ $${usd < 1 ? usd.toFixed(2) : usd.toFixed(0)} USD`;
}

function getAppFAQ(app) {
  const specific = (APP_FAQ[app.appId] || []).map((item, i) => i === 0 ? { ...item, featured: true } : item);
  const license = (app.isOpenSource ? APP_FAQ._openSource : APP_FAQ._hlsl).map((item, i) => i === 0 ? { ...item, featured: true } : item);
  const common = APP_FAQ._common.map((item, i) => i === 1 ? { ...item, featured: true } : item);
  return [...specific, ...license, ...common];
}

function getAppReviews(app) {
  return APP_REVIEWS[app.appId] || [];
}

function getAvgRating(reviews) {
  if (!reviews.length) return 0;
  return reviews.reduce((s, r) => s + r.rating, 0) / reviews.length;
}

/* ─── Detail Page ──────────────────────────────────────────────────────────── */

function DetailPage({ app, onClose, onInstall, initialTab, initialDevSubTab }) {
  const reviews = useMemo(() => getAppReviews(app), [app]);
  const avgRating = useMemo(() => getAvgRating(reviews), [reviews]);
  const faq = useMemo(() => getAppFAQ(app), [app]);
  const docs = APP_DOCS[app.appId] || '';
  const versions = APP_VERSIONS[app.appId] || [];
  const appFees = APP_FEES[app.appId] || [];
  const platformFees = APP_FEES._platform;
  const githubUrl = APP_GITHUB[app.appId] || app.codeLink || '';

  const featuredFaqSet = useMemo(() => {
    const s = new Set();
    faq.forEach((item, i) => { if (item.featured) s.add(i); });
    return s;
  }, [faq]);

  const [tab, setTab] = useState(initialTab || 'overview');
  const [openFaq, setOpenFaq] = useState(() => new Set(featuredFaqSet));
  const [userRevs, setUserRevs] = useState(() => getUserReviews(app.appId));
  const [showReviewForm, setShowReviewForm] = useState(false);
  const [reviewDraft, setReviewDraft] = useState({ author: '', rating: 5, title: '', text: '' });
  const [featureWishes, setFeatureWishes] = useState(() => getFeatureWishes(app.appId));
  const [fwVotes, setFwVotes] = useState(() => getMyFWVotes());
  const [fwDraft, setFwDraft] = useState({ text: '', author: '' });
  const [showFwForm, setShowFwForm] = useState(false);
  const [bugReports, setBugReports] = useState(() => getBugReports(app.appId));
  const [bugVotes, setBugVotes] = useState(() => getMyBugVotes());
  const [bugDraft, setBugDraft] = useState({ title: '', description: '', author: '' });
  const [showBugForm, setShowBugForm] = useState(false);
  const [devSubTab, setDevSubTab] = useState(initialDevSubTab || 'suggestions');

  useEffect(() => {
    const h = (e) => e.key === "Escape" && onClose();
    window.scrollTo(0, 0);
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  useEffect(() => { setTab(initialTab || 'overview'); setOpenFaq(new Set(featuredFaqSet)); setUserRevs(getUserReviews(app.appId)); setShowReviewForm(false); setReviewDraft({ author: '', rating: 5, title: '', text: '' }); setFeatureWishes(getFeatureWishes(app.appId)); setFwVotes(getMyFWVotes()); setFwDraft({ text: '', author: '' }); setShowFwForm(false); setBugReports(getBugReports(app.appId)); setBugVotes(getMyBugVotes()); setBugDraft({ title: '', description: '', author: '' }); setShowBugForm(false); setDevSubTab(initialDevSubTab || 'suggestions'); }, [app.appId, featuredFaqSet, initialTab, initialDevSubTab]);

  if (!app) return null;

  const rows = [
    ["VERSION", app.version || "—"],
    ["BUILD", app.versionNumber ?? "—"],
    ["AUTHOR", <>
      {app.author?.name || "—"}
      {app.author?.githubUsername && (
        <a href={`https://github.com/${app.author.githubUsername}`} target="_blank"
          rel="noreferrer" style={{ marginLeft: 8, fontSize: 11 }}>
          @{app.author.githubUsername}
        </a>
      )}
    </>],
    ["UPSTREAM", app.upstreamAuthor || "—"],
    ["DEPLOYED", fmtDate(app.createdAt)],
    ["PKG_ID", <code key="p" style={{
      fontSize: 10, color: T.cyan + "88", wordBreak: "break-all",
      fontFamily: "'JetBrains Mono', monospace",
    }}>{app.packageId}</code>],
  ];

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'versions', label: `Versions (${versions.length})` },
    { id: 'faq', label: `FAQ (${faq.length})` },
    { id: 'audits', label: '🔍 Audits' },
    { id: 'sidecars', label: '🪝 Grapple & Sidecars' },
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
      {/* ── Pricing Module ── */}
      <div style={{ maxWidth: 780, marginBottom: 28 }}>
        {/* App Price */}
        <div style={{
          padding: 28, background: T.surface, borderRadius: T.radius,
          border: `1px solid ${T.green}33`, marginBottom: 20,
          backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
        }}>
          <SectionHeader color={T.green}>App Price</SectionHeader>
          <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
            {(() => {
              const pr = getAppPrice(app.appId);
              const isFree = pr.price === 'FREE';
              const isZeroSol = !isFree && pr.price.match(/^0(\.0*)?\s*SOL$/);
              const priceColor = (isFree || isZeroSol) ? T.green : T.cyan;
              const priceGlow = (isFree || isZeroSol) ? T.greenGlow : T.accentGlow;
              const usd = solToUsd(pr.price);
              const origUsd = solToUsd(pr.originalPrice || '');
              return (
                <>
                  <span style={{
                    fontSize: 36, fontWeight: 900, color: priceColor,
                    fontFamily: "'Orbitron', sans-serif",
                    textShadow: `0 0 15px ${priceGlow}`,
                  }}>{pr.price}</span>
                  {usd && <span style={{ fontSize: 14, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{usd}</span>}
                  {pr.onSale && pr.originalPrice && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{
                        fontSize: 18, color: T.textDim, textDecoration: 'line-through',
                        fontFamily: "'JetBrains Mono', monospace",
                      }}>{pr.originalPrice}</span>
                      {origUsd && <span style={{ fontSize: 12, color: T.textDim + '99', textDecoration: 'line-through', fontFamily: "'JetBrains Mono', monospace" }}>{origUsd}</span>}
                      <span style={{
                        display: 'inline-block', padding: '3px 10px',
                        background: '#f5a623', color: '#1a1a2e',
                        fontSize: 10, fontWeight: 800, borderRadius: 3,
                        fontFamily: "'Orbitron', sans-serif",
                        letterSpacing: '.06em',
                        boxShadow: '0 2px 8px rgba(245,166,35,0.4)',
                      }}>ON SALE</span>
                    </div>
                  )}
                  {!isFree && !isZeroSol && (
                    <span style={{ fontSize: 11, color: T.textDim, lineHeight: 1.5, fontStyle: 'italic', fontFamily: "'JetBrains Mono', monospace", marginTop: 4, display: 'block' }}>
                      SOL prices are approximate. Actual cost may vary with market rate.
                    </span>
                  )}
                </>
              );
            })()}
            <span style={{ fontSize: 13, color: T.textSec, lineHeight: 1.6 }}>
              {platformFees.selfHosted.description}
            </span>
          </div>
        </div>

        {/* Third-Party API Fees */}
        {appFees.length > 0 && (
          <div style={{
            padding: 24, background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.peach}33`, marginBottom: 20,
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <SectionHeader color={T.peach}>Third-Party Services</SectionHeader>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {appFees.map((fee, i) => (
                <div key={i} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "flex-start",
                  gap: 16, padding: "12px 16px",
                  border: `1px solid ${T.borderLight}`, borderRadius: T.radiusSm,
                }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: T.text }}>{fee.service}</div>
                    <div style={{ fontSize: 11, color: T.textDim, marginTop: 2 }}>{fee.note}</div>
                  </div>
                  <Badge neon={fee.cost === 'Free' ? T.green : T.peach}>{fee.cost}</Badge>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

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
              {timeAgo(latestVersionDate(app.appId) || app.createdAt) && (
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                  {'\u00b7'} updated {timeAgo(latestVersionDate(app.appId) || app.createdAt)}
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

  /* ---- GRAPPLE & SIDECARS TAB ---- */
  const appSidecars = getAppSidecars(app.appId);
  const hasSidecars = appSidecars.sidecars.length > 0;
  const hasGrapple = appSidecars.grapple.length > 0;

  const grappleTableStyle = {
    width: '100%', borderCollapse: 'separate', borderSpacing: 0,
    fontSize: 13, fontFamily: "'JetBrains Mono', monospace",
  };
  const gThStyle = {
    padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 700,
    letterSpacing: '.1em', textTransform: 'uppercase',
    borderBottom: `2px solid ${T.cyan}44`, color: T.textDim,
    fontFamily: "'JetBrains Mono', monospace",
  };
  const gTdStyle = {
    padding: '10px 14px', borderBottom: `1px solid ${T.border}`,
    color: T.textSec, fontSize: 12, lineHeight: 1.6, verticalAlign: 'top',
  };

  const SidecarsTab = () => (
    <div style={{ maxWidth: 780 }}>
      {/* Info box */}
      <div style={{
        padding: 22, background: T.cyan + '08', borderRadius: T.radius,
        border: `1px solid ${T.cyan}33`, marginBottom: 24,
        backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
          <span style={{
            fontSize: 24, width: 44, height: 44, borderRadius: 3, flexShrink: 0,
            display: "flex", alignItems: "center", justifyContent: "center",
            background: T.cyan + '15', border: `1px solid ${T.cyan}33`,
          }}>{'🪝'}</span>
          <div>
            <div style={{
              fontSize: 16, fontWeight: 800, color: T.cyan, marginBottom: 6,
              fontFamily: "'Orbitron', sans-serif",
              textShadow: `0 0 8px ${T.accentGlow}`,
            }}>Grapple &amp; Sidecars</div>
            <div style={{ fontSize: 13, color: T.textSec, lineHeight: 1.7 }}>
              <strong style={{ color: T.text }}>Grapple</strong> is the <em>only</em> way a Pearl can access
              another Pearl — or the wider internet. Each connection is a scoped Cap{"'"}n Proto capability:
              one Pearl offers a capability, the other accepts it, and the link is forged only
              when the user Grapples the two together. Nothing connects silently, and every
              connection has a named direction, purpose, and authority level.
            </div>
            <div style={{ fontSize: 13, color: T.textSec, lineHeight: 1.7, marginTop: 8 }}>
              <strong style={{ color: T.text }}>Sidecars</strong> are major server-level services that run
              one-per-server on your Melusina instance — things like an email relay or an AI model proxy.
              They{"'"}re available only through Melusina, managed by the platform, and shared across
              all Pearls that need them. Individual apps don{"'"}t install or control sidecars — the
              server admin provisions them once.
            </div>
            <a href="https://melusina-os.org/docs/grapple" target="_blank" rel="noreferrer"
              style={{
                display: "inline-flex", alignItems: "center", gap: 6, marginTop: 12,
                fontSize: 12, color: T.cyan, textDecoration: "none",
                fontFamily: "'JetBrains Mono', monospace", fontWeight: 600,
                transition: "all .2s",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.textShadow = `0 0 8px ${T.accentGlow}`; }}
              onMouseLeave={(e) => { e.currentTarget.style.textShadow = "none"; }}
            >Learn more on Melusina-Os.org {'\u2192'}</a>
          </div>
        </div>
      </div>

      {/* ─── Grapple Connections (ABOVE sidecars) ─── */}
      <div style={{ marginBottom: 28 }}>
        <SectionHeader color={T.yellow}>{'🪝'} Grapple Connections</SectionHeader>
        {hasGrapple ? (
          <div style={{
            background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.yellow}33`, overflow: 'hidden',
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <table style={grappleTableStyle}>
              <thead>
                <tr>
                  <th style={gThStyle}>Direction</th>
                  <th style={gThStyle}>Cap{"'"}n Proto Capability</th>
                  <th style={gThStyle}>App(s)</th>
                  <th style={gThStyle}>Purpose</th>
                  <th style={gThStyle}>Type</th>
                </tr>
              </thead>
              <tbody>
                {appSidecars.grapple.map((g, i) => (
                  <tr key={i} style={{
                    background: i % 2 === 0 ? 'transparent' : T.bg + '44',
                  }}>
                    <td style={gTdStyle}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 5,
                        fontSize: 11, fontWeight: 700,
                        color: g.direction === 'incoming' ? T.green : T.cyan,
                      }}>
                        {g.direction === 'incoming' ? '\u2B07\uFE0F' : '\u2B06\uFE0F'}
                        {g.direction === 'incoming' ? ' IN' : ' OUT'}
                      </span>
                    </td>
                    <td style={gTdStyle}>
                      <code style={{
                        padding: '3px 8px', borderRadius: 3, fontSize: 11,
                        background: T.cyan + '15', color: T.cyan,
                        border: `1px solid ${T.cyan}33`,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}>{g.capability}</code>
                    </td>
                    <td style={{ ...gTdStyle, color: T.text, fontWeight: 600, fontSize: 12 }}>
                      {g.apps.join(', ')}
                    </td>
                    <td style={gTdStyle}>{g.purpose}</td>
                    <td style={gTdStyle}>
                      <span style={{
                        fontSize: 9, fontWeight: 700, padding: '2px 8px', borderRadius: 3,
                        fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.06em',
                        textTransform: 'uppercase',
                        background: g.type === 'dependency' ? T.magenta + '22' : T.yellow + '22',
                        color: g.type === 'dependency' ? T.magenta : T.yellow,
                        border: `1px solid ${g.type === 'dependency' ? T.magenta + '44' : T.yellow + '44'}`,
                      }}>{g.type === 'dependency' ? 'DEP' : 'ENHANCE'}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{
            padding: 28, textAlign: 'center', background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.border}`,
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <div style={{ fontSize: 13, color: T.textDim, lineHeight: 1.7 }}>
              No Grapple connections — this app runs without Pearl-to-Pearl or internet access.
            </div>
          </div>
        )}
      </div>

      {/* ─── Sidecars (BELOW grapple) ─── */}
      <div style={{ marginBottom: 28 }}>
        <SectionHeader color={T.magenta}>{'🏍\uFE0F'} Sidecars</SectionHeader>
        {hasSidecars ? (
          <>
          <div style={{
            background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.magenta}33`, overflow: 'hidden',
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <table style={grappleTableStyle}>
              <thead>
                <tr>
                  <th style={{ ...gThStyle, borderBottomColor: T.magenta + '44' }}>Required</th>
                  <th style={{ ...gThStyle, borderBottomColor: T.magenta + '44' }}>Sidecar Name</th>
                  <th style={{ ...gThStyle, borderBottomColor: T.magenta + '44' }}>Service Type</th>
                  <th style={{ ...gThStyle, borderBottomColor: T.magenta + '44' }}>Description</th>
                </tr>
              </thead>
              <tbody>
                {appSidecars.sidecars.map((sc, i) => (
                  <tr key={i} style={{
                    background: i % 2 === 0 ? 'transparent' : T.bg + '44',
                  }}>
                    <td style={gTdStyle}>
                      <span style={{
                        fontSize: 9, fontWeight: 700, padding: '2px 8px', borderRadius: 3,
                        fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.06em',
                        textTransform: 'uppercase',
                        background: sc.required ? T.magenta + '22' : T.yellow + '22',
                        color: sc.required ? T.magenta : T.yellow,
                        border: `1px solid ${sc.required ? T.magenta + '44' : T.yellow + '44'}`,
                      }}>{sc.required ? 'REQUIRED' : 'OPTIONAL'}</span>
                    </td>
                    <td style={{ ...gTdStyle, color: T.text, fontWeight: 600, fontSize: 12 }}>
                      {sc.name}
                    </td>
                    <td style={gTdStyle}>
                      <span style={{
                        fontSize: 9, fontWeight: 600, padding: '2px 8px', borderRadius: 3,
                        fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.08em',
                        background: T.cyan + '15', color: T.cyan + 'cc', border: `1px solid ${T.cyan}33`,
                        textTransform: 'uppercase',
                      }}>{sc.type}</span>
                    </td>
                    <td style={gTdStyle}>
                      {sc.description}
                      {sc.links && sc.links.length > 0 && (
                        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 8 }}>
                          {sc.links.map((lnk, j) => (
                            <a key={j} href={lnk.url} target="_blank" rel="noreferrer" style={{
                              fontSize: 11, color: T.cyan, textDecoration: 'none',
                              fontFamily: "'JetBrains Mono', monospace", fontWeight: 600,
                              transition: 'all .2s',
                            }}
                              onMouseEnter={(e) => { e.currentTarget.style.textShadow = `0 0 8px ${T.accentGlow}`; }}
                              onMouseLeave={(e) => { e.currentTarget.style.textShadow = 'none'; }}
                            >{lnk.label} {'\u2192'}</a>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {/* Supported backends (below table) */}
          {appSidecars.sidecars.filter(sc => sc.options && sc.options.length > 0).map((sc, i) => (
            <div key={`opts-${i}`} style={{ marginTop: 16 }}>
              <div style={{
                fontSize: 11, fontWeight: 700, color: T.textDim, marginBottom: 8,
                fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.08em',
              }}>SUPPORTED BACKENDS — {sc.name.toUpperCase()}</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
                {sc.options.map((opt, j) => (
                  <a key={j} href={opt.url} target="_blank" rel="noreferrer" style={{
                    padding: 14, background: T.bg + 'cc', borderRadius: T.radiusSm,
                    border: `1px solid ${T.border}`, textDecoration: 'none',
                    transition: 'all .2s',
                  }}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = T.cyan + '55'; e.currentTarget.style.boxShadow = `0 0 12px ${T.accentGlow}`; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.boxShadow = 'none'; }}
                  >
                    <div style={{
                      fontSize: 13, fontWeight: 700, color: T.cyan, marginBottom: 4,
                      fontFamily: "'Orbitron', sans-serif",
                    }}>{opt.name}</div>
                    <div style={{ fontSize: 11, color: T.textDim, lineHeight: 1.5 }}>{opt.description}</div>
                  </a>
                ))}
              </div>
            </div>
          ))}
          </>
        ) : (
          <div style={{
            padding: 28, textAlign: 'center', background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.border}`,
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <div style={{ fontSize: 13, color: T.textDim, lineHeight: 1.7 }}>
              No server-level sidecars required — this app runs entirely within its Pearl.
            </div>
          </div>
        )}
      </div>
    </div>
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
            }}>{app.isOpenSource ? 'AGPLv3 License' : 'HLSL License'}</div>
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
            app.isOpenSource ? '✓ Community contributions welcome' : '✓ Converts to AGPLv3 after 3 years',
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
          {app.isOpenSource ? OPEN_SOURCE_LICENSE_TEXT : HLSL_LICENSE_TEXT}
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

  /* ---- AUDITS TAB ---- */
  const appAudits = APP_AUDITS[app.appId] || { ai: [], human: [] };
  const AuditsTab = () => {
    const [aiPage, setAiPage] = useState(0);
    const aiAudit = appAudits.ai[aiPage] || null;
    const currentVersion = app.version || versions[0]?.version || '—';
    /* find the latest human audit, and check if it matches current version */
    const latestHuman = appAudits.human.length > 0 ? appAudits.human[0] : null;
    const humanMatchesCurrent = latestHuman && latestHuman.version === currentVersion;

    const ratingColor = (r) => r === 'Pass' ? T.green : r === 'Partial' ? T.yellow : T.magenta;
    const ratingGlow = (r) => r === 'Pass' ? T.greenGlow : r === 'Partial' ? T.yellow + '44' : T.magentaGlow;

    return (
      <div style={{ maxWidth: 780 }}>
        {/* AI Audits */}
        <div style={{
          padding: 28, background: T.surface, borderRadius: T.radius,
          border: `1px solid ${T.cyan}33`, marginBottom: 24,
          backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 20 }}>
            <SectionHeader color={T.cyan}>🤖 AI Audit</SectionHeader>
            {appAudits.ai.length > 1 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button onClick={() => setAiPage(Math.min(aiPage + 1, appAudits.ai.length - 1))} disabled={aiPage >= appAudits.ai.length - 1}
                  style={{ background: 'none', border: `1px solid ${T.border}`, borderRadius: 3, color: aiPage >= appAudits.ai.length - 1 ? T.textDim + '44' : T.cyan, fontSize: 12, padding: '4px 10px', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace" }}>← Older</button>
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{aiPage + 1}/{appAudits.ai.length}</span>
                <button onClick={() => setAiPage(Math.max(aiPage - 1, 0))} disabled={aiPage <= 0}
                  style={{ background: 'none', border: `1px solid ${T.border}`, borderRadius: 3, color: aiPage <= 0 ? T.textDim + '44' : T.cyan, fontSize: 12, padding: '4px 10px', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace" }}>Newer →</button>
              </div>
            )}
          </div>

          {aiAudit ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 14, fontWeight: 700, color: T.cyan, fontFamily: "'Orbitron', sans-serif", textShadow: `0 0 6px ${T.accentGlow}` }}>v{aiAudit.version}</span>
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{aiAudit.date}</span>
                {aiAudit.version !== currentVersion && (
                  <span style={{ fontSize: 10, padding: '2px 8px', background: T.yellow + '22', border: `1px solid ${T.yellow}44`, borderRadius: 3, color: T.yellow, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>Not current version</span>
                )}
              </div>
              {/* Results table */}
              <div style={{ border: `1px solid ${T.border}`, borderRadius: T.radiusSm, overflow: 'hidden', marginBottom: 16 }}>
                {AUDIT_CATEGORIES.map((cat, i) => {
                  const r = aiAudit.results[cat.key];
                  if (!r) return null;
                  return (
                    <div key={cat.key} style={{
                      display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 16px',
                      borderBottom: i < AUDIT_CATEGORIES.length - 1 ? `1px solid ${T.borderLight}` : 'none',
                      background: i % 2 === 0 ? 'transparent' : T.bg + '44',
                    }}>
                      <span style={{ fontSize: 15, flexShrink: 0, width: 24, textAlign: 'center' }}>{cat.icon}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: T.text, marginBottom: 2 }}>{cat.label}</div>
                        <div style={{ fontSize: 11, color: T.textDim, lineHeight: 1.5 }}>{r.note}</div>
                      </div>
                      <span style={{
                        fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 3,
                        color: ratingColor(r.rating), background: ratingColor(r.rating) + '15',
                        border: `1px solid ${ratingColor(r.rating)}33`,
                        fontFamily: "'JetBrains Mono', monospace",
                        textShadow: `0 0 4px ${ratingGlow(r.rating)}`,
                        flexShrink: 0, whiteSpace: 'nowrap',
                      }}>{r.rating}</span>
                    </div>
                  );
                })}
              </div>
              {/* AI conversation links */}
              {aiAudit.links && Object.keys(aiAudit.links).length > 0 && (
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace", alignSelf: 'center' }}>View conversation:</span>
                  {aiAudit.links.chatgpt && <a href={aiAudit.links.chatgpt} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: T.green, fontFamily: "'JetBrains Mono', monospace", textDecoration: 'none', padding: '3px 10px', border: `1px solid ${T.green}33`, borderRadius: 3, transition: 'all .2s' }}   onMouseEnter={(e) => { e.currentTarget.style.background = T.green + '15'; }} onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>ChatGPT ↗</a>}
                  {aiAudit.links.claude && <a href={aiAudit.links.claude} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: T.peach, fontFamily: "'JetBrains Mono', monospace", textDecoration: 'none', padding: '3px 10px', border: `1px solid ${T.peach}33`, borderRadius: 3, transition: 'all .2s' }}   onMouseEnter={(e) => { e.currentTarget.style.background = T.peach + '15'; }} onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>Claude ↗</a>}
                  {aiAudit.links.gemini && <a href={aiAudit.links.gemini} target="_blank" rel="noreferrer" style={{ fontSize: 11, color: T.purple, fontFamily: "'JetBrains Mono', monospace", textDecoration: 'none', padding: '3px 10px', border: `1px solid ${T.purple}33`, borderRadius: 3, transition: 'all .2s' }}   onMouseEnter={(e) => { e.currentTarget.style.background = T.purple + '15'; }} onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}>Gemini ↗</a>}
                </div>
              )}
            </>
          ) : (
            <div style={{ fontSize: 13, color: T.textDim, fontStyle: 'italic', padding: 20, textAlign: 'center' }}>
              No AI audits available for this app yet.
            </div>
          )}
        </div>

        {/* Human Audits */}
        <div style={{
          padding: 28, background: T.surface, borderRadius: T.radius,
          border: `1px solid ${T.yellow}33`,
          backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
        }}>
          <SectionHeader color={T.yellow}>👤 Human Audit</SectionHeader>
          {latestHuman ? (
            <div>
              {!humanMatchesCurrent && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16,
                  padding: '10px 14px', background: T.yellow + '0c', border: `1px solid ${T.yellow}33`,
                  borderRadius: T.radiusSm,
                }}>
                  <span style={{ fontSize: 14 }}>⚠️</span>
                  <span style={{ fontSize: 12, color: T.yellow, fontFamily: "'JetBrains Mono', monospace" }}>
                    No human audit for current version (v{currentVersion}). Showing latest: v{latestHuman.version}
                  </span>
                </div>
              )}
              <div style={{ border: `1px solid ${T.border}`, borderRadius: T.radiusSm, overflow: 'hidden' }}>
                <div style={{ padding: '14px 16px', borderBottom: `1px solid ${T.borderLight}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontSize: 13, fontWeight: 700, color: T.yellow, fontFamily: "'Orbitron', sans-serif" }}>v{latestHuman.version}</span>
                    <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{latestHuman.date}</span>
                  </div>
                  <span style={{ fontSize: 11, color: T.textSec, fontFamily: "'JetBrains Mono', monospace" }}>{latestHuman.auditor}</span>
                </div>
                <div style={{ padding: '14px 16px' }}>
                  <div style={{ fontSize: 13, lineHeight: 1.7, color: T.textSec }}>{latestHuman.summary}</div>
                  {latestHuman.reportUrl && latestHuman.reportUrl !== '#' && (
                    <a href={latestHuman.reportUrl} target="_blank" rel="noreferrer" style={{ display: 'inline-block', marginTop: 10, fontSize: 11, color: T.yellow, fontFamily: "'JetBrains Mono', monospace", textDecoration: 'none', padding: '4px 12px', border: `1px solid ${T.yellow}33`, borderRadius: 3 }}>View Full Report ↗</a>
                  )}
                </div>
              </div>
              {/* scroll back through all human audits if multiple */}
              {appAudits.human.length > 1 && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace", marginBottom: 8 }}>Previous human audits:</div>
                  {appAudits.human.slice(1).map((h, i) => (
                    <div key={i} style={{
                      padding: '10px 14px', marginBottom: 8,
                      border: `1px solid ${T.borderLight}`, borderRadius: T.radiusSm,
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: T.textSec, fontFamily: "'JetBrains Mono', monospace" }}>v{h.version}</span>
                        <span style={{ fontSize: 10, color: T.textDim }}>{h.date}</span>
                      </div>
                      <span style={{ fontSize: 10, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{h.auditor}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: 13, color: T.textDim, fontStyle: 'italic', padding: 20, textAlign: 'center' }}>
              No human audits available for this app yet. Audits are performed periodically by the Harbor Life Security Team.
            </div>
          )}
        </div>
      </div>
    );
  };

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

  /* ---- VERSIONS TAB ---- */
  const VersionsTab = () => (
    <div style={{ maxWidth: 780 }}>
      <SectionHeader>Version History</SectionHeader>
      {versions.length === 0 ? (
        <div style={{ textAlign: "center", padding: "60px 20px" }}>
          <div style={{ fontSize: 36, marginBottom: 16, opacity: 0.3 }}>📋</div>
          <p style={{ color: T.textDim, fontSize: 14, fontFamily: "'JetBrains Mono', monospace" }}>
            Version history coming soon
          </p>
        </div>
      ) : (
        <div style={{ position: "relative", paddingLeft: 28, marginTop: 16 }}>
          <div style={{ position: "absolute", left: 5, top: 0, bottom: 0, width: 2, background: `linear-gradient(180deg, ${T.cyan}44, ${T.purple}22, transparent)` }} />
          {versions.map((v, i) => (
            <div key={i} style={{ position: "relative", marginBottom: 32, animation: `fadeUp .3s ease-out ${i * 0.08}s both` }}>
              <div style={{
                position: "absolute", left: -28, top: 4, width: 12, height: 12,
                borderRadius: "50%", background: i === 0 ? T.cyan : T.bgAlt,
                border: `2px solid ${i === 0 ? T.cyan : T.textDim + '44'}`,
                boxShadow: i === 0 ? `0 0 10px ${T.cyan}66` : "none",
              }} />
              <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 10, flexWrap: "wrap" }}>
                <span style={{
                  fontSize: 16, fontWeight: 800,
                  color: i === 0 ? T.cyan : T.text,
                  fontFamily: "'Orbitron', sans-serif",
                  textShadow: i === 0 ? `0 0 8px ${T.accentGlow}` : "none",
                }}>v{v.version}</span>
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{v.date}</span>
                {i === 0 && <Badge neon={T.cyan}>Latest</Badge>}
              </div>
              <div style={{
                padding: "16px 20px", background: T.surface,
                borderRadius: T.radius, border: `1px solid ${i === 0 ? T.cyan + '22' : T.border}`,
                backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
              }}>
                {v.changes.map((c, j) => (
                  <div key={j} style={{
                    fontSize: 13, color: T.textSec, lineHeight: 1.8,
                    paddingLeft: 16, position: "relative",
                  }}>
                    <span style={{ position: "absolute", left: 0, color: T.cyan, fontSize: 11, textShadow: `0 0 4px ${T.accentGlow}` }}>▸</span>
                    {c}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
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
            <div key={i} className="faq-item" style={{
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
            {/* USP selling points in detail hero */}
            {(APP_USP[app.appId] || []).length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
                {(APP_USP[app.appId] || []).map((usp, ui) => (
                  <div key={ui} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 8,
                    fontSize: 14, lineHeight: 1.5, color: T.textSec,
                  }}>
                    <span style={{ color: T.green, flexShrink: 0, fontSize: 15, textShadow: `0 0 6px ${T.greenGlow}` }}>✓</span>
                    <span>{usp}</span>
                  </div>
                ))}
              </div>
            )}
            {reviews.length > 0 && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
                <StarRating rating={avgRating} size={14} />
                <span style={{ fontSize: 12, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
                  {avgRating.toFixed(1)} ({reviews.length})
                </span>
              </div>
            )}
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
            <a href={app.webLink} target="_blank" rel="noreferrer" style={{
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
            <a href={app.codeLink} target="_blank" rel="noreferrer" style={{
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
            <a href={githubUrl + '#readme'} target="_blank" rel="noreferrer" style={{
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

        {/* price + license row */}
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: 'center', marginBottom: 16 }}>
          {(() => {
            const pr = getAppPrice(app.appId);
            const isFree = pr.price === 'FREE';
            const isZeroSol = !isFree && pr.price.match(/^0(\.0*)?\s*SOL$/);
            const priceColor = (isFree || isZeroSol) ? T.green : T.cyan;
            const priceGlow = (isFree || isZeroSol) ? T.greenGlow : T.accentGlow;
            const usd = solToUsd(pr.price);
            return (
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.06em', textTransform: 'uppercase' }}>Price</span>
                <span style={{ fontSize: 20, fontWeight: 800, color: priceColor, fontFamily: "'Orbitron', sans-serif", textShadow: `0 0 10px ${priceGlow}` }}>{pr.price}</span>
                {usd && <span style={{ fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>{usd}</span>}
                {pr.onSale && pr.originalPrice && (
                  <span style={{ fontSize: 12, color: T.textDim, textDecoration: 'line-through', fontFamily: "'JetBrains Mono', monospace" }}>{pr.originalPrice}</span>
                )}
              </div>
            );
          })()}
          <span style={{ width: 1, height: 18, background: T.border }} />
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
            >{app.isOpenSource ? 'Open Source' : 'HLSL'}</button>
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
          {tab === 'versions' && <VersionsTab />}
          {tab === 'faq' && <FAQTab />}
          {tab === 'audits' && <AuditsTab />}
          {tab === 'sidecars' && <SidecarsTab />}
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
            <div style={{ fontSize: 12, color: T.textDim, fontFamily: "'JetBrains Mono', monospace" }}>
              {(() => { const p = APP_PRICES[app.appId]; return p ? p.price : "FREE"; })()}
            </div>
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
  const hostRef = React.useRef(localStorage.getItem("sandstormHost") || "");
  const [installModalApp, setInstallModalApp] = useState(null);
  const [showGetMelusina, setShowGetMelusina] = useState(false);

  useEffect(() => {
    const src = Array.isArray(data) ? data : data.apps || [];
    setApps(src.map((a) => ({ ...a, categories: a.categories || [] })));
  }, []);



  /* ─── ?host= URL parameter: auto-register server on open ─── */
  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const hostParam = params.get('host');
      if (!hostParam) return;
      const h = sanitizeHost(hostParam);
      if (!h) return;

      // Check if it matches a known pbay server
      const domain = h.replace(/^https?:\/\//i, '').toLowerCase();
      const pbayMatch = PBAY_SERVERS.find((s) => domain === s.domain || domain.endsWith('.' + s.domain));
      if (pbayMatch) {
        setPbayServer(pbayMatch);
      } else {
        addPrivateServer(h);
      }

      // Persist to legacy localStorage key
      localStorage.setItem("sandstormHost", h);
      hostRef.current = h;

      // Clean the URL without reloading
      const url = new URL(window.location);
      url.searchParams.delete('host');
      window.history.replaceState({}, '', url.pathname + url.search + url.hash);
    } catch { /* in-app browsers may restrict URL APIs — fail silently */ }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

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

      {/* alpha test banner */}
      <div style={{ maxWidth: 1440, margin: '0 auto', padding: '16px 24px 0' }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 14, padding: '14px 20px',
          background: `linear-gradient(135deg, ${T.green}08, ${T.cyan}06)`,
          border: `1px solid ${T.green}33`, borderRadius: T.radius,
          backdropFilter: 'blur(12px)', WebkitBackdropFilter: 'blur(12px)',
        }}>
          <span style={{ fontSize: 22, flexShrink: 0 }}>🧪</span>
          <div style={{ fontSize: 13, color: T.textSec, lineHeight: 1.6 }}>
            <strong style={{ color: T.green, fontFamily: "'Orbitron', sans-serif", fontSize: 11, letterSpacing: '.06em' }}>ALPHA TEST PHASE</strong>
            <span style={{ margin: '0 8px', color: T.border }}>|</span>
            All apps are <strong style={{ color: T.green }}>free of charge</strong> during the alpha.
            Licenses obtained now are <strong style={{ color: T.cyan }}>free perpetually</strong> — hurry to test and keep!
          </div>
        </div>
      </div>

      {/* grid */}
      <main style={{ maxWidth: 1440, margin: "0 auto", padding: "20px 24px 80px" }}>
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20
        }}>
          <span style={{
            fontSize: 11, color: T.textDim,
            fontFamily: "'JetBrains Mono', monospace",
            letterSpacing: ".06em",
          }}>
            <span style={{ color: T.cyan + "aa" }}>{filtered.length}</span>
            {" "}app{filtered.length !== 1 ? "s" : ""}
            {category !== "All" && <> in <span style={{ color: T.magenta + "aa" }}>{category}</span></>}
          </span>
        </div>

        {filtered.length > 0 ? (
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 310px), 1fr))",
            gap: 16,
          }}>
            {filtered.map((app, i) => (
              <div key={app.appId} style={{ animationDelay: `${i * 60}ms` }}>
                <AppCard app={app} onSelect={onSelect} onInstall={onInstall} onVersionClick={(id) => onSelect(id, 'versions')} />
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

createRoot(document.getElementById("root")).render(<App />);
