import React, { useEffect, useMemo, useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { format } from "date-fns";
import data from "./apps.json";

const APP_INDEX_BASE = "https://hrbrlife.github.io/melusina-static-store";

/* ─── helpers ──────────────────────────────────────────────────────────────── */

const sanitizeHost = (h) => {
  if (!h) return "";
  const t = h.trim();
  return (!/^https?:\/\//i.test(t) ? `https://${t}` : t).replace(/\/+$/, "");
};

const fmtDate = (v) => {
  if (!v) return "—";
  const ts = typeof v === "number" ? v : Date.parse(v);
  return Number.isNaN(ts) ? String(v) : format(ts, "MMM d, yyyy");
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

/* ─── design tokens (light) ───────────────────────────────────────────────── */

const T = {
  bg: "#f5f5f7",
  surface: "#ffffff",
  card: "#ffffff",
  cardHover: "#f8f6ff",
  border: "#e2e2ea",
  borderLight: "#efefef",
  accent: "#6c47d9",
  accentHover: "#5a38c4",
  accentGlow: "rgba(108,71,217,.18)",
  green: "#16a34a",
  text: "#1a1a2e",
  textSec: "#5c5c78",
  textDim: "#9898ad",
  radius: 14,
  radiusSm: 10,
};

/* ─── global CSS ───────────────────────────────────────────────────────────── */

const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px;-webkit-text-size-adjust:100%}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:${T.bg};color:${T.text};overflow-x:hidden;min-height:100dvh;
}
a{color:${T.accent};text-decoration:none}
a:hover{color:${T.accentHover}}
::selection{background:${T.accentGlow};color:${T.text}}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:${T.border};border-radius:3px}
input,select,button{font:inherit;color:inherit}
img{display:block;max-width:100%}

@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes pop{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:none}}

.cat-scroll::-webkit-scrollbar{display:none}
.cat-scroll{scrollbar-width:none}

.ss-strip{display:flex;gap:10px;overflow-x:auto;padding:4px 0 10px;scroll-snap-type:x mandatory;-webkit-overflow-scrolling:touch}
.ss-strip::-webkit-scrollbar{height:4px}
.ss-strip::-webkit-scrollbar-thumb{background:${T.border};border-radius:2px}
.ss-strip img{scroll-snap-align:start;border-radius:10px;border:1px solid ${T.border};cursor:pointer;transition:transform .15s,border-color .15s,box-shadow .15s;object-fit:cover;flex-shrink:0}
.ss-strip img:hover{transform:scale(1.03);border-color:${T.accent};box-shadow:0 4px 16px ${T.accentGlow}}

.card-shots{display:flex;gap:6px;overflow-x:auto;padding:2px 0;-webkit-overflow-scrolling:touch;scrollbar-width:none}
.card-shots::-webkit-scrollbar{display:none}
.card-shots img{border-radius:8px;border:1px solid ${T.border};object-fit:cover;flex-shrink:0;cursor:pointer;transition:border-color .15s}
.card-shots img:hover{border-color:${T.accent}}

.lightbox-overlay{position:fixed;inset:0;z-index:900;background:rgba(0,0,0,.85);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);display:flex;align-items:center;justify-content:center;animation:fadeIn .2s ease-out;cursor:zoom-out}
.lightbox-overlay img{max-width:92vw;max-height:88vh;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.5);animation:pop .2s ease-out}

.detail-grid{display:grid;grid-template-columns:1fr 320px;gap:24px;align-items:start}
@media(max-width:720px){.detail-grid{grid-template-columns:1fr}}
`;

/* ─── small components ─────────────────────────────────────────────────────── */

function Badge({ children, color }) {
  return (
    <span style={{
      display: "inline-block", padding: "3px 10px", fontSize: 11,
      fontWeight: 600, letterSpacing: ".03em", borderRadius: 20,
      background: color || T.borderLight, color: T.textSec, whiteSpace: "nowrap",
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
        background: `linear-gradient(135deg, ${T.accent}, #9b6dff)`,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: size * .42, fontWeight: 700, color: "#fff", flexShrink: 0,
      }}>
        {letter}
      </div>
    );
  }
  return (
    <img src={src} alt="" loading="lazy" onError={() => setErr(true)}
      style={{
        width: size, height: size, borderRadius: T.radiusSm,
        objectFit: "contain", background: T.bg, flexShrink: 0,
      }}
    />
  );
}

/* ─── Connect-server dropdown ──────────────────────────────────────────────── */

function HostBar({ host, setHost }) {
  const [open, setOpen] = useState(false);
  const ok = !!host.trim();
  return (
    <div style={{ position: "relative" }}>
      <button onClick={() => setOpen(!open)} style={{
        display: "flex", alignItems: "center", gap: 8, padding: "8px 14px",
        border: `1px solid ${ok ? T.green : T.border}`,
        borderRadius: T.radiusSm, background: ok ? "rgba(22,163,74,.06)" : T.surface,
        cursor: "pointer", fontSize: 13, color: ok ? T.green : T.textSec, transition: "all .2s",
      }}>
        <span style={{ fontSize: 10 }}>{ok ? "●" : "○"}</span>
        <span>{ok ? "Connected" : "Connect"}</span>
        <span style={{ fontSize: 9, opacity: .5 }}>▾</span>
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 99 }} />
          <div style={{
            position: "absolute", right: 0, top: "calc(100% + 8px)",
            background: T.surface, border: `1px solid ${T.border}`, borderRadius: T.radius,
            padding: 18, zIndex: 100, width: 300,
            boxShadow: "0 12px 40px rgba(0,0,0,.12)", animation: "pop .15s ease-out",
          }}>
            <label style={{
              display: "block", fontSize: 11, fontWeight: 700, textTransform: "uppercase",
              letterSpacing: ".06em", color: T.textSec, marginBottom: 8,
            }}>Sandstorm Server URL</label>
            <input type="url" placeholder="https://sandstorm.example.com" value={host}
              onChange={(e) => setHost(e.target.value)} autoFocus
              style={{
                width: "100%", padding: "10px 12px", background: T.bg,
                border: `1px solid ${T.border}`, borderRadius: 8, color: T.text,
                fontSize: 14, outline: "none",
              }}
              onFocus={(e) => (e.target.style.borderColor = T.accent)}
              onBlur={(e) => (e.target.style.borderColor = T.border)}
            />
            <p style={{ fontSize: 11, color: T.textDim, marginTop: 8, lineHeight: 1.5 }}>
              Enter your Sandstorm address to enable&nbsp;one-click&nbsp;installs.
            </p>
          </div>
        </>
      )}
    </div>
  );
}

/* ─── App Card (with screenshot thumbnails) ────────────────────────────────── */

function AppCard({ app, onSelect, host }) {
  const [hov, setHov] = useState(false);
  const url = installUrl(host, app);
  const shots = app.screenshots || [];

  return (
    <div role="button" tabIndex={0}
      onClick={() => onSelect(app.appId)}
      onKeyDown={(e) => e.key === "Enter" && onSelect(app.appId)}
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{
        background: hov ? T.cardHover : T.card,
        border: `1px solid ${hov ? "rgba(108,71,217,.35)" : T.border}`,
        borderRadius: T.radius, cursor: "pointer",
        transition: "all .2s ease",
        transform: hov ? "translateY(-2px)" : "none",
        boxShadow: hov ? "0 8px 28px rgba(0,0,0,.08)" : "0 1px 3px rgba(0,0,0,.05)",
        display: "flex", flexDirection: "column",
        animation: "fadeUp .4s ease-out both",
        height: "100%", overflow: "hidden",
      }}
    >
      {/* screenshot thumbnails */}
      {shots.length > 0 && (
        <div className="card-shots" style={{ padding: "10px 10px 0" }}>
          {shots.slice(0, 4).map((s, i) => (
            <img key={i} src={screenshotUrl(app.appId, s)}
              alt={shotCaption(s) || `Screenshot ${i + 1}`}
              loading="lazy"
              style={{ width: 120, height: 75 }}
              onClick={(e) => { e.stopPropagation(); onSelect(app.appId); }}
              onError={(e) => { e.target.style.display = "none"; }}
            />
          ))}
        </div>
      )}

      <div style={{ padding: "14px 16px 16px", display: "flex", flexDirection: "column", gap: 12, flex: 1 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
          <AppIcon app={app} size={48} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <h3 style={{
              fontSize: 15, fontWeight: 700, margin: 0, color: T.text,
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>{app.name}</h3>
            <p style={{
              fontSize: 13, color: T.textSec, margin: "4px 0 0", lineHeight: 1.45,
              display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical",
              overflow: "hidden",
            }}>
              {app.shortDescription || app.summary || ""}
            </p>
          </div>
        </div>

        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          gap: 8, marginTop: "auto",
        }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", minWidth: 0 }}>
            {(app.categories || []).slice(0, 2).map((c) => <Badge key={c}>{c}</Badge>)}
          </div>
          {url ? (
            <a href={url} target="_blank" rel="noreferrer"
              onClick={(e) => e.stopPropagation()}
              style={{
                display: "inline-flex", alignItems: "center", gap: 5,
                padding: "7px 18px", background: T.accent, color: "#fff",
                fontWeight: 600, fontSize: 12, borderRadius: 20, whiteSpace: "nowrap",
                textDecoration: "none", boxShadow: `0 2px 10px ${T.accentGlow}`,
                transition: "all .15s",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = T.accentHover; e.currentTarget.style.transform = "scale(1.05)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = T.accent; e.currentTarget.style.transform = "none"; }}
            >Install</a>
          ) : (
            <span style={{ fontSize: 12, color: T.textDim, whiteSpace: "nowrap" }}>
              v{app.version || app.versionNumber || "—"}
            </span>
          )}
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
          fontSize: 11, fontWeight: 700, textTransform: "uppercase",
          letterSpacing: ".07em", color: T.textSec, marginBottom: 12,
        }}>Screenshots</div>
        <div className="ss-strip">
          {screenshots.map((s, i) => (
            <div key={i} style={{ flexShrink: 0, display: "flex", flexDirection: "column", gap: 6 }}>
              <img src={screenshotUrl(appId, s)} alt={shotCaption(s) || `Screenshot ${i + 1}`}
                onClick={() => setLightbox(i)}
                style={{ width: 320, height: 200 }}
                onError={(e) => { e.target.parentElement.style.display = "none"; }}
              />
              {shotCaption(s) && (
                <span style={{ fontSize: 12, color: T.textDim, maxWidth: 320, lineHeight: 1.4 }}>
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
              background: "rgba(0,0,0,.5)", border: "1px solid rgba(255,255,255,.2)",
              color: "#fff", width: 44, height: 44, borderRadius: "50%",
              fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
            }}>‹</button>
          )}
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, maxWidth: "92vw" }}>
            <img src={screenshotUrl(appId, screenshots[lightbox])} alt="" onClick={(e) => e.stopPropagation()} style={{ cursor: "default" }} />
            {shotCaption(screenshots[lightbox]) && (
              <p style={{ color: "rgba(255,255,255,.85)", fontSize: 14, textAlign: "center", maxWidth: 600 }}>
                {shotCaption(screenshots[lightbox])}
              </p>
            )}
            <span style={{ color: "rgba(255,255,255,.4)", fontSize: 12 }}>
              {lightbox + 1} / {screenshots.length}
            </span>
          </div>
          {screenshots.length > 1 && (
            <button onClick={(e) => { e.stopPropagation(); next(); }} style={{
              position: "absolute", right: 16, top: "50%", transform: "translateY(-50%)",
              background: "rgba(0,0,0,.5)", border: "1px solid rgba(255,255,255,.2)",
              color: "#fff", width: 44, height: 44, borderRadius: "50%",
              fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center",
            }}>›</button>
          )}
        </div>
      )}
    </>
  );
}

/* ─── Detail Page (fullscreen, replaces grid) ──────────────────────────────── */

function DetailPage({ app, host, onClose }) {
  const url = installUrl(host, app);

  useEffect(() => {
    const h = (e) => e.key === "Escape" && onClose();
    window.scrollTo(0, 0);
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  if (!app) return null;

  const rows = [
    ["Version", app.version || "—"],
    ["Build", app.versionNumber ?? "—"],
    ["Author", <>
      {app.author?.name || "—"}
      {app.author?.githubUsername && (
        <a href={`https://github.com/${app.author.githubUsername}`} target="_blank"
          rel="noreferrer" style={{ marginLeft: 8, fontSize: 12 }}>
          @{app.author.githubUsername}
        </a>
      )}
    </>],
    ["Upstream", app.upstreamAuthor || "—"],
    ["Published", fmtDate(app.createdAt)],
    ["License", app.isOpenSource ? "Open Source" : "BSL 1.1 (→ AGPLv3 after 2 years)"],
    ["Package ID", <code key="p" style={{ fontSize: 11, color: T.textDim, wordBreak: "break-all" }}>{app.packageId}</code>],
  ];

  return (
    <div style={{ minHeight: "100dvh", background: T.bg, animation: "fadeIn .15s ease-out" }}>
      {/* top bar */}
      <div style={{
        position: "sticky", top: 0, zIndex: 200,
        background: "rgba(255,255,255,.88)",
        backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)",
        borderBottom: `1px solid ${T.border}`,
      }}>
        <div style={{
          maxWidth: 960, margin: "0 auto", padding: "12px 24px",
          display: "flex", alignItems: "center", gap: 14,
        }}>
          <button onClick={onClose} style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "7px 16px", borderRadius: 8,
            border: `1px solid ${T.border}`, background: T.surface,
            color: T.textSec, fontSize: 13, fontWeight: 600,
            cursor: "pointer", transition: "all .15s",
          }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = T.accent; e.currentTarget.style.color = T.accent; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = T.border; e.currentTarget.style.color = T.textSec; }}
          >← Back</button>
          <span style={{ fontSize: 15, fontWeight: 700, color: T.text }}>{app.name}</span>
        </div>
      </div>

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "32px 24px 80px" }}>
        {/* hero */}
        <div style={{ display: "flex", gap: 24, alignItems: "center", marginBottom: 32, flexWrap: "wrap" }}>
          <AppIcon app={app} size={88} />
          <div style={{ flex: 1, minWidth: 240 }}>
            <h1 style={{ fontSize: 32, fontWeight: 800, margin: 0, letterSpacing: "-.03em", color: T.text }}>
              {app.name}
            </h1>
            <p style={{ color: T.textSec, fontSize: 16, margin: "10px 0 0", lineHeight: 1.5 }}>
              {app.shortDescription || app.summary || ""}
            </p>
          </div>
        </div>

        {/* actions */}
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 32 }}>
          {url ? (
            <a href={url} target="_blank" rel="noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              padding: "14px 36px", background: T.accent, color: "#fff",
              fontWeight: 700, fontSize: 15, borderRadius: 12, textDecoration: "none",
              boxShadow: `0 4px 20px ${T.accentGlow}`, transition: "transform .15s, background .15s",
            }}
              onMouseEnter={(e) => { e.currentTarget.style.transform = "scale(1.03)"; e.currentTarget.style.background = T.accentHover; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = "none"; e.currentTarget.style.background = T.accent; }}
            ><span style={{ fontSize: 18 }}>↓</span> Install App</a>
          ) : (
            <div style={{
              padding: "14px 28px", background: T.surface, color: T.textDim,
              borderRadius: 12, fontSize: 14, border: `1px solid ${T.border}`,
            }}>Connect your server to install</div>
          )}
          {app.webLink && (
            <a href={app.webLink} target="_blank" rel="noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "14px 24px", background: T.surface,
              border: `1px solid ${T.border}`, color: T.text,
              fontWeight: 600, fontSize: 14, borderRadius: 12,
              textDecoration: "none", transition: "border-color .15s",
            }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = T.accent)}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = T.border)}
            >Website ↗</a>
          )}
          {app.codeLink && (
            <a href={app.codeLink} target="_blank" rel="noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "14px 24px", background: T.surface,
              border: `1px solid ${T.border}`, color: T.text,
              fontWeight: 600, fontSize: 14, borderRadius: 12,
              textDecoration: "none", transition: "border-color .15s",
            }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = T.accent)}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = T.border)}
            >Source ↗</a>
          )}
        </div>

        {/* tags */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 32 }}>
          {(app.categories || []).map((c) => <Badge key={c} color={T.accent + "18"}>{c}</Badge>)}
          {app.isOpenSource && <Badge color="rgba(22,163,74,.12)">Open Source</Badge>}
          {!app.isOpenSource && <Badge color="rgba(234,88,12,.12)">BSL 1.1</Badge>}
        </div>

        {/* screenshots */}
        <ScreenshotGallery screenshots={app.screenshots} appId={app.appId} />

        {/* description + info sidebar */}
        <div className="detail-grid">
          <div>
            {app.description && (
              <div style={{
                padding: 24, background: T.surface,
                borderRadius: T.radius, border: `1px solid ${T.border}`,
              }}>
                <div style={{
                  fontSize: 11, fontWeight: 700, textTransform: "uppercase",
                  letterSpacing: ".07em", color: T.textSec, marginBottom: 14,
                }}>About</div>
                <div style={{ fontSize: 14, lineHeight: 1.75, color: T.text, whiteSpace: "pre-wrap" }}>
                  {app.description}
                </div>
              </div>
            )}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{
              background: T.surface, borderRadius: T.radius,
              border: `1px solid ${T.border}`, overflow: "hidden",
            }}>
              <div style={{
                padding: "14px 20px", borderBottom: `1px solid ${T.border}`,
                fontSize: 11, fontWeight: 700, textTransform: "uppercase",
                letterSpacing: ".07em", color: T.textSec,
              }}>Details</div>
              {rows.map(([label, val], i) => (
                <div key={label} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "flex-start",
                  gap: 12, padding: "12px 20px",
                  borderBottom: i < rows.length - 1 ? `1px solid ${T.borderLight}` : "none",
                  fontSize: 13,
                }}>
                  <span style={{ color: T.textSec, flexShrink: 0 }}>{label}</span>
                  <span style={{ textAlign: "right", wordBreak: "break-word" }}>{val}</span>
                </div>
              ))}
            </div>

            <div style={{
              padding: "14px 20px", background: T.surface,
              borderRadius: T.radiusSm, border: `1px solid ${T.border}`,
            }}>
              <span style={{
                display: "block", fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                letterSpacing: ".07em", color: T.textDim, marginBottom: 6,
              }}>App ID</span>
              <code style={{ fontSize: 11, color: T.textSec, wordBreak: "break-all", lineHeight: 1.6 }}>
                {app.appId}
              </code>
            </div>
          </div>
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
  const [host, setHost] = useState(localStorage.getItem("sandstormHost") || "");

  useEffect(() => {
    const src = Array.isArray(data) ? data : data.apps || [];
    setApps(src.map((a) => ({ ...a, categories: a.categories || [] })));
  }, []);

  useEffect(() => { if (host) localStorage.setItem("sandstormHost", host); }, [host]);

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
  const onSelect = useCallback((id) => setSelectedId(id), []);
  const onClose = useCallback(() => setSelectedId(null), []);

  /* fullscreen detail replaces the grid view */
  if (selectedApp) {
    return (
      <>
        <style>{CSS}</style>
        <DetailPage app={selectedApp} host={host} onClose={onClose} />
      </>
    );
  }

  return (
    <>
      <style>{CSS}</style>

      {/* header */}
      <header style={{
        position: "sticky", top: 0, zIndex: 200,
        background: "rgba(255,255,255,.88)",
        backdropFilter: "blur(20px) saturate(1.4)",
        WebkitBackdropFilter: "blur(20px) saturate(1.4)",
        borderBottom: `1px solid ${T.border}`,
      }}>
        <div style={{
          maxWidth: 1200, margin: "0 auto", padding: "12px 20px",
          display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: "auto" }}>
            <div style={{
              width: 34, height: 34, borderRadius: 10,
              background: `linear-gradient(135deg, ${T.accent}, #9b6dff)`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 17, fontWeight: 900, color: "#fff",
              boxShadow: `0 2px 10px ${T.accentGlow}`,
            }}>M</div>
            <span style={{ fontSize: 17, fontWeight: 800, letterSpacing: "-.02em", color: T.text }}>
              Melusina
              <span style={{ color: T.textSec, fontWeight: 400, marginLeft: 6, fontSize: 15 }}>
                App Market
              </span>
            </span>
          </div>

          <div style={{ position: "relative", flex: "1 1 180px", maxWidth: 340 }}>
            <span style={{
              position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)",
              fontSize: 14, color: T.textDim, pointerEvents: "none",
            }}>⌕</span>
            <input type="search" placeholder="Search apps..." value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{
                width: "100%", padding: "9px 14px 9px 34px", background: T.surface,
                border: `1px solid ${T.border}`, borderRadius: 10, color: T.text,
                fontSize: 14, outline: "none", transition: "border-color .15s",
              }}
              onFocus={(e) => (e.target.style.borderColor = T.accent)}
              onBlur={(e) => (e.target.style.borderColor = T.border)}
            />
          </div>

          <HostBar host={host} setHost={setHost} />
        </div>
      </header>

      {/* categories */}
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "16px 20px 0" }}>
        <div className="cat-scroll" style={{
          display: "flex", gap: 8, overflowX: "auto", paddingBottom: 6,
          WebkitOverflowScrolling: "touch",
        }}>
          {categories.map((c) => {
            const active = category === c;
            return (
              <button key={c} onClick={() => setCategory(c)} style={{
                padding: "7px 18px", borderRadius: 20, border: "none",
                background: active ? T.accent : T.surface,
                color: active ? "#fff" : T.textSec,
                fontSize: 13, fontWeight: 600, cursor: "pointer",
                whiteSpace: "nowrap", transition: "all .15s", flexShrink: 0,
                boxShadow: active ? `0 2px 10px ${T.accentGlow}` : "none",
              }}>{c}</button>
            );
          })}
        </div>
      </div>

      {/* grid */}
      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "20px 20px 80px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
          <span style={{ fontSize: 13, color: T.textDim }}>
            {filtered.length} app{filtered.length !== 1 ? "s" : ""}
            {category !== "All" ? ` in ${category}` : ""}
          </span>
        </div>

        {filtered.length > 0 ? (
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 320px), 1fr))",
            gap: 16,
          }}>
            {filtered.map((app, i) => (
              <div key={app.appId} style={{ animationDelay: `${i * 40}ms` }}>
                <AppCard app={app} onSelect={onSelect} host={host} />
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: "center", padding: "80px 20px", color: T.textDim }}>
            <div style={{ fontSize: 48, marginBottom: 16, opacity: .3 }}>⌕</div>
            <p style={{ fontSize: 16, fontWeight: 600, color: T.textSec }}>No apps found</p>
            <p style={{ fontSize: 14, marginTop: 6 }}>Try a different search or category</p>
          </div>
        )}
      </main>
    </>
  );
}

createRoot(document.getElementById("root")).render(<App />);
