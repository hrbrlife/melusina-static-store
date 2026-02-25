#!/usr/bin/env python3
"""Insert pbay.app install flow into main.jsx"""

import sys

with open('src/main.jsx', 'r', encoding='utf-8') as f:
    content = f.read()

# Find insertion point by unique substring
needle = 'user reviews (localStorage until backend)'
idx = content.find(needle)
if idx < 0:
    print("ERROR: Could not find marker", file=sys.stderr)
    sys.exit(1)

# Go to start of the comment line
line_start = content.rfind('\n', 0, idx)
insert_at = line_start + 1  # after the newline

new_block = """\
/* \u2500\u2500\u2500 pbay.app jurisdiction servers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */

const PBAY_SERVERS = [
  { code: 'LU', flag: '\U0001F1F1\U0001F1FA', name: 'Luxembourg', domain: 'lu.pbay.app', region: 'Europe' },
  { code: 'CH', flag: '\U0001F1E8\U0001F1ED', name: 'Switzerland', domain: 'ch.pbay.app', region: 'Europe' },
  { code: 'DE', flag: '\U0001F1E9\U0001F1EA', name: 'Germany', domain: 'de.pbay.app', region: 'Europe' },
  { code: 'FR', flag: '\U0001F1EB\U0001F1F7', name: 'France', domain: 'fr.pbay.app', region: 'Europe' },
  { code: 'NL', flag: '\U0001F1F3\U0001F1F1', name: 'Netherlands', domain: 'nl.pbay.app', region: 'Europe' },
  { code: 'FI', flag: '\U0001F1EB\U0001F1EE', name: 'Finland', domain: 'fi.pbay.app', region: 'Europe' },
  { code: 'IS', flag: '\U0001F1EE\U0001F1F8', name: 'Iceland', domain: 'is.pbay.app', region: 'Europe' },
  { code: 'US', flag: '\U0001F1FA\U0001F1F8', name: 'United States', domain: 'us.pbay.app', region: 'Americas' },
  { code: 'CA', flag: '\U0001F1E8\U0001F1E6', name: 'Canada', domain: 'ca.pbay.app', region: 'Americas' },
  { code: 'SG', flag: '\U0001F1F8\U0001F1EC', name: 'Singapore', domain: 'sg.pbay.app', region: 'Asia-Pacific' },
  { code: 'JP', flag: '\U0001F1EF\U0001F1F5', name: 'Japan', domain: 'jp.pbay.app', region: 'Asia-Pacific' },
];

/* pbay / private server localStorage helpers */
const PBAY_KEY = 'melusina_pbay_server';
const PRIV_KEY = 'melusina_private_servers';

const getPbayServer = () => {
  try { return JSON.parse(localStorage.getItem(PBAY_KEY)); } catch { return null; }
};
const setPbayServer = (srv) => { localStorage.setItem(PBAY_KEY, JSON.stringify(srv)); };

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

/* \u2500\u2500\u2500 Jurisdiction Picker Modal \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */

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
        width: 560, maxWidth: '92vw', maxHeight: '88vh', overflowY: 'auto',
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
            }}>\u00D7</button>
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
            Melusina installation at any time \u2014 no lock-in.
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
                      }}>{srv.flag} {srv.code} \u2014 {srv.domain}</div>
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

/* \u2500\u2500\u2500 Install Destination Modal \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 */

function InstallModal({ app, onClose }) {
  const [section, setSection] = useState('pbay');
  const [showJurisdiction, setShowJurisdiction] = useState(false);
  const [pbayServer, setPbayServerState] = useState(() => getPbayServer());
  const [privateServers, setPrivateServers] = useState(() => getPrivateServers());
  const [newPrivate, setNewPrivate] = useState('');
  const [addingPrivate, setAddingPrivate] = useState(false);

  const doInstall = useCallback((host) => {
    const h = sanitizeHost(host);
    if (!h || !app.packageId) return;
    const pkg = app.packageUrl || `${APP_INDEX_BASE}/packages/${app.packageId}`;
    window.open(`${h}/install/${app.packageId}?url=${encodeURIComponent(pkg)}`, '_blank');
    onClose();
  }, [app, onClose]);

  const selectPbay = useCallback((srv) => {
    setPbayServer(srv);
    setPbayServerState(srv);
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
        width: 520, maxWidth: '92vw', maxHeight: '88vh', overflowY: 'auto',
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
            }}>\u00D7</button>
          </div>
        </div>

        {/* section tabs */}
        <div style={{ display: 'flex', borderBottom: `1px solid ${T.purple}22` }}>
          <button style={sectionTabStyle(section === 'pbay')} onClick={() => setSection('pbay')}>
            \U0001F310 pbay.app
          </button>
          <button style={sectionTabStyle(section === 'private')} onClick={() => setSection('private')}>
            \U0001F5A5\uFE0F Private Servers
          </button>
        </div>

        {/* \u2500\u2500\u2500 pbay.app section \u2500\u2500\u2500 */}
        {section === 'pbay' && (
          <div style={{ padding: '24px 28px 28px' }}>
            {pbayServer ? (
              <>
                <div style={{
                  fontSize: 10, fontWeight: 700, color: T.textDim, marginBottom: 10,
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: '.1em', textTransform: 'uppercase',
                }}>YOUR PBAY SERVER</div>
                <button onClick={() => doInstall(`https://${pbayServer.domain}`)} style={{
                  display: 'flex', alignItems: 'center', gap: 14, width: '100%',
                  padding: '18px 22px', background: T.cyan + '11',
                  border: `1px solid ${T.cyan}44`,
                  borderRadius: T.radiusSm, cursor: 'pointer',
                  transition: 'all .2s', textAlign: 'left',
                  marginBottom: 16,
                }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = T.cyan + '88';
                    e.currentTarget.style.boxShadow = `0 0 25px ${T.accentGlow}`;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = T.cyan + '44';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  <span style={{ fontSize: 28 }}>{pbayServer.flag}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{
                      fontSize: 14, fontWeight: 800, color: T.text,
                      fontFamily: "'Orbitron', sans-serif",
                    }}>{pbayServer.flag} {pbayServer.code} \u2014 {pbayServer.domain}</div>
                    <div style={{
                      fontSize: 11, color: T.textDim, fontFamily: "'JetBrains Mono', monospace",
                    }}>{pbayServer.name}</div>
                  </div>
                  <span style={{
                    padding: '8px 20px', borderRadius: 3,
                    background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`,
                    border: `1px solid ${T.cyan}55`,
                    color: T.cyan, fontSize: 11, fontWeight: 700,
                    fontFamily: "'Orbitron', sans-serif",
                    letterSpacing: '.08em',
                    textShadow: `0 0 8px ${T.accentGlow}`,
                  }}>\u2193 INSTALL</span>
                </button>
                <button onClick={() => setShowJurisdiction(true)} style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: T.cyan, fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 600, padding: 0, transition: 'all .2s',
                }}
                  onMouseEnter={(e) => { e.currentTarget.style.textShadow = `0 0 8px ${T.accentGlow}`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.textShadow = 'none'; }}
                >Change jurisdiction \u2192</button>
              </>
            ) : (
              <>
                <div style={{
                  padding: 24, background: T.yellow + '08', borderRadius: T.radiusSm,
                  border: `1px solid ${T.yellow}33`, marginBottom: 20,
                }}>
                  <div style={{
                    fontSize: 13, fontWeight: 700, color: T.yellow, marginBottom: 8,
                    fontFamily: "'Orbitron', sans-serif",
                  }}>Jurisdiction-Isolated Hosting</div>
                  <div style={{
                    fontSize: 12, color: T.textSec, lineHeight: 1.8,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>
                    Each pbay.app server is <strong style={{ color: T.text }}>legally, physically, and
                    operationally isolated</strong> to a single jurisdiction. Your data, compute, and legal
                    agreements stay entirely within the borders of the country you choose.
                  </div>
                  <div style={{
                    fontSize: 11, color: T.textDim, lineHeight: 1.7, marginTop: 10,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}>
                    This is for SaaS pbay hosting only. You can export and move your Pearls
                    to a private Melusina installation at any time \u2014 no lock-in.
                  </div>
                </div>
                <button onClick={() => setShowJurisdiction(true)} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
                  width: '100%', padding: '16px 20px',
                  background: `linear-gradient(135deg, ${T.cyan}18, ${T.magenta}12)`,
                  border: `1px solid ${T.cyan}55`,
                  borderRadius: T.radiusSm, cursor: 'pointer',
                  color: T.cyan, fontSize: 13, fontWeight: 700,
                  fontFamily: "'Orbitron', sans-serif",
                  letterSpacing: '.08em', textTransform: 'uppercase',
                  textShadow: `0 0 8px ${T.accentGlow}`,
                  boxShadow: `0 0 15px ${T.accentGlow}`,
                  transition: 'all .2s',
                }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.boxShadow = `0 0 30px ${T.accentGlow}`;
                    e.currentTarget.style.transform = 'scale(1.02)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.boxShadow = `0 0 15px ${T.accentGlow}`;
                    e.currentTarget.style.transform = 'none';
                  }}
                >\U0001F310 Choose Jurisdiction</button>
              </>
            )}
          </div>
        )}

        {/* \u2500\u2500\u2500 Private Servers section \u2500\u2500\u2500 */}
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
                      }}>\U0001F5A5\uFE0F</span>
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
                      >\u00D7</button>
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
                  >\u2193 CONNECT & INSTALL</button>
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

"""

content = content[:insert_at] + new_block + content[insert_at:]

with open('src/main.jsx', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done: inserted pbay data + modals")
