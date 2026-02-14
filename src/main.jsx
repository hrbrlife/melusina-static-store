import React, { useEffect, useMemo, useState, useCallback } from "react";
import { createRoot } from "react-dom/client";
import { format } from "date-fns";
import data from "./apps.json";

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

/* ─── cyberpunk design tokens ─────────────────────────────────────────────── */

const T = {
  bg: "#07070d",
  bgAlt: "#0c0c18",
  surface: "rgba(12, 12, 28, 0.85)",
  card: "rgba(15, 15, 35, 0.7)",
  cardHover: "rgba(20, 20, 50, 0.85)",
  border: "rgba(0, 255, 255, 0.1)",
  borderHover: "rgba(0, 255, 255, 0.4)",
  borderLight: "rgba(0, 255, 255, 0.06)",
  cyan: "#00f0ff",
  magenta: "#ff2d8a",
  green: "#00ff88",
  purple: "#a855f7",
  yellow: "#ffd000",
  accent: "#00f0ff",
  accentHover: "#00d4e0",
  accentGlow: "rgba(0, 240, 255, 0.25)",
  magentaGlow: "rgba(255, 45, 138, 0.25)",
  greenGlow: "rgba(0, 255, 136, 0.2)",
  text: "#e8e8f0",
  textSec: "#8888a8",
  textDim: "#55556a",
  radius: 4,
  radiusSm: 3,
};

/* ─── global CSS ───────────────────────────────────────────────────────────── */

const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px;-webkit-text-size-adjust:100%}
body{
  font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:${T.bg};
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
    linear-gradient(${T.cyan}08 1px, transparent 1px),
    linear-gradient(90deg, ${T.cyan}08 1px, transparent 1px);
  background-size:60px 60px;
  mask-image:radial-gradient(ellipse 80% 60% at 50% 0%,black 30%,transparent 80%);
  -webkit-mask-image:radial-gradient(ellipse 80% 60% at 50% 0%,black 30%,transparent 80%);
}
body::after{
  content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:
    radial-gradient(ellipse 600px 400px at 20% 10%, ${T.cyan}09, transparent),
    radial-gradient(ellipse 500px 500px at 80% 80%, ${T.magenta}08, transparent),
    radial-gradient(ellipse 400px 300px at 50% 50%, ${T.purple}06, transparent);
}

@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes pop{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:none}}
@keyframes glowPulse{
  0%,100%{box-shadow:0 0 5px ${T.cyan}33,0 0 20px ${T.cyan}11,inset 0 0 15px ${T.cyan}08}
  50%{box-shadow:0 0 10px ${T.cyan}55,0 0 40px ${T.cyan}22,inset 0 0 25px ${T.cyan}11}
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

.card-shots{display:flex;gap:6px;overflow-x:auto;padding:2px 0;-webkit-overflow-scrolling:touch;scrollbar-width:none}
.card-shots::-webkit-scrollbar{display:none}
.card-shots img{
  border-radius:3px;border:1px solid ${T.border};
  object-fit:cover;flex-shrink:0;cursor:pointer;
  transition:border-color .2s,box-shadow .2s;
}
.card-shots img:hover{border-color:${T.cyan};box-shadow:0 0 12px ${T.accentGlow}}

.lightbox-overlay{
  position:fixed;inset:0;z-index:900;
  background:rgba(0,0,0,.92);
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

.detail-grid{display:grid;grid-template-columns:1fr 320px;gap:24px;align-items:start}
@media(max-width:720px){.detail-grid{grid-template-columns:1fr}}
@media(max-width:480px){html{font-size:14px}}

.neon-text{
  color:${T.cyan};
  text-shadow:0 0 7px ${T.cyan}88,0 0 20px ${T.cyan}44,0 0 40px ${T.cyan}22;
}
`;

/* ─── small components ─────────────────────────────────────────────────────── */

function Badge({ children, neon }) {
  const base = neon || T.cyan;
  return (
    <span style={{
      display: "inline-block", padding: "4px 12px", fontSize: 10,
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

/* ─── Connect-server dropdown ──────────────────────────────────────────────── */

function HostBar({ host, setHost }) {
  const [open, setOpen] = useState(false);
  const ok = !!host.trim();
  return (
    <div style={{ position: "relative" }}>
      <button onClick={() => setOpen(!open)} style={{
        display: "flex", alignItems: "center", gap: 8, padding: "8px 16px",
        border: `1px solid ${ok ? T.green + "66" : T.cyan + "33"}`,
        borderRadius: T.radiusSm, background: ok ? T.green + "11" : "rgba(0,240,255,0.05)",
        cursor: "pointer", fontSize: 12, color: ok ? T.green : T.cyan,
        fontFamily: "'JetBrains Mono', monospace", fontWeight: 600,
        letterSpacing: ".05em", textTransform: "uppercase",
        transition: "all .3s ease",
        textShadow: `0 0 8px ${ok ? T.greenGlow : T.accentGlow}`,
        boxShadow: `0 0 10px ${ok ? T.greenGlow : T.accentGlow}`,
      }}>
        <span style={{
          width: 6, height: 6, borderRadius: "50%",
          background: ok ? T.green : T.cyan,
          boxShadow: `0 0 6px ${ok ? T.green : T.cyan}`,
        }} />
        <span>{ok ? "LINKED" : "CONNECT"}</span>
        <span style={{ fontSize: 8, opacity: .6 }}>▾</span>
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 99 }} />
          <div style={{
            position: "absolute", right: 0, top: "calc(100% + 8px)",
            background: "rgba(10, 10, 25, 0.95)",
            border: `1px solid ${T.cyan}44`,
            borderRadius: T.radius,
            padding: 20, zIndex: 100, width: 320,
            boxShadow: `0 0 30px ${T.accentGlow}, 0 20px 60px rgba(0,0,0,.5)`,
            backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)",
            animation: "pop .15s ease-out",
          }}>
            <label style={{
              display: "block", fontSize: 10, fontWeight: 700, textTransform: "uppercase",
              letterSpacing: ".12em", color: T.cyan, marginBottom: 10,
              fontFamily: "'Orbitron', sans-serif",
              textShadow: `0 0 6px ${T.accentGlow}`,
            }}>SERVER ENDPOINT</label>
            <input type="url" placeholder="https://sandstorm.example.com" value={host}
              onChange={(e) => setHost(e.target.value)} autoFocus
              style={{
                width: "100%", padding: "12px 14px", background: "rgba(0,240,255,0.04)",
                border: `1px solid ${T.cyan}33`, borderRadius: 3, color: T.text,
                fontSize: 13, outline: "none", transition: "border-color .2s, box-shadow .2s",
                fontFamily: "'JetBrains Mono', monospace",
              }}
              onFocus={(e) => {
                e.target.style.borderColor = T.cyan + "88";
                e.target.style.boxShadow = `0 0 15px ${T.accentGlow}`;
              }}
              onBlur={(e) => {
                e.target.style.borderColor = T.cyan + "33";
                e.target.style.boxShadow = "none";
              }}
            />
            <p style={{
              fontSize: 11, color: T.textDim, marginTop: 10, lineHeight: 1.6,
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              Enter your Sandstorm address to enable one-click installs.
            </p>
          </div>
        </>
      )}
    </div>
  );
}

/* ─── App Card ─────────────────────────────────────────────────────────────── */

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
        position: "relative",
        background: hov ? T.cardHover : T.card,
        border: `1px solid ${hov ? T.cyan + "55" : T.cyan + "18"}`,
        borderRadius: T.radius, cursor: "pointer",
        transition: "all .3s ease",
        transform: hov ? "translateY(-3px)" : "none",
        boxShadow: hov
          ? `0 0 25px ${T.accentGlow}, 0 10px 40px rgba(0,0,0,.4), inset 0 0 30px ${T.cyan}06`
          : `0 2px 10px rgba(0,0,0,.3), inset 0 0 20px ${T.cyan}04`,
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
            background: `linear-gradient(90deg, transparent, ${T.cyan}44, transparent)`,
            animation: "scanLine 1.5s linear infinite",
          }} />
        </div>
      )}

      {/* corner accent */}
      <div style={{
        position: "absolute", top: 0, right: 0, width: 30, height: 30,
        borderBottom: `1px solid ${hov ? T.cyan + "44" : T.cyan + "15"}`,
        borderLeft: `1px solid ${hov ? T.cyan + "44" : T.cyan + "15"}`,
        borderRadius: `0 ${T.radius}px 0 0`,
        transition: "border-color .3s",
      }} />

      {/* screenshots */}
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

      <div style={{ padding: "14px 16px 16px", display: "flex", flexDirection: "column", gap: 12, flex: 1, position: "relative", zIndex: 2 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
          <AppIcon app={app} size={48} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <h3 style={{
              fontSize: 14, fontWeight: 700, margin: 0,
              fontFamily: "'Orbitron', sans-serif",
              color: hov ? T.cyan : T.text,
              textShadow: hov ? `0 0 10px ${T.accentGlow}` : "none",
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              transition: "color .3s, text-shadow .3s",
              letterSpacing: ".02em",
            }}>{app.name}</h3>
            <p style={{
              fontSize: 12, color: T.textSec, margin: "6px 0 0", lineHeight: 1.5,
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
                padding: "7px 18px",
                background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`,
                border: `1px solid ${T.cyan}66`,
                color: T.cyan,
                fontFamily: "'Orbitron', sans-serif",
                fontWeight: 700, fontSize: 10, letterSpacing: ".1em",
                textTransform: "uppercase",
                borderRadius: 2, whiteSpace: "nowrap",
                textDecoration: "none",
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
            >INSTALL</a>
          ) : (
            <span style={{
              fontSize: 11, color: T.cyan + "88",
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 500, letterSpacing: ".05em",
              textShadow: `0 0 5px ${T.cyan}22`,
            }}>
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

/* ─── Detail Page ──────────────────────────────────────────────────────────── */

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
    ["LICENSE", app.isOpenSource ? "Open Source" : "HLSL → AGPLv3 after 3y"],
    ["PKG_ID", <code key="p" style={{
      fontSize: 10, color: T.cyan + "88", wordBreak: "break-all",
      fontFamily: "'JetBrains Mono', monospace",
    }}>{app.packageId}</code>],
  ];

  return (
    <div style={{ minHeight: "100dvh", background: T.bg, animation: "fadeIn .15s ease-out" }}>
      {/* top bar */}
      <div style={{
        position: "sticky", top: 0, zIndex: 200,
        background: "rgba(7, 7, 13, 0.9)",
        backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)",
        borderBottom: `1px solid ${T.cyan}22`,
      }}>
        <div style={{
          maxWidth: 960, margin: "0 auto", padding: "12px 20px",
          display: "flex", alignItems: "center", gap: 14,
        }}>
          <button onClick={onClose} style={{
            display: "flex", alignItems: "center", gap: 6,
            padding: "8px 18px", borderRadius: 3,
            border: `1px solid ${T.cyan}33`, background: T.cyan + "08",
            color: T.cyan, fontSize: 12, fontWeight: 600,
            cursor: "pointer", transition: "all .2s",
            fontFamily: "'JetBrains Mono', monospace",
            letterSpacing: ".05em",
            textShadow: `0 0 6px ${T.accentGlow}`,
          }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = T.cyan + "77";
              e.currentTarget.style.boxShadow = `0 0 15px ${T.accentGlow}`;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = T.cyan + "33";
              e.currentTarget.style.boxShadow = "none";
            }}
          >← BACK</button>
          <span style={{
            fontSize: 14, fontWeight: 700, color: T.text,
            fontFamily: "'Orbitron', sans-serif",
            letterSpacing: ".03em",
          }}>{app.name}</span>
        </div>
      </div>

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "32px 20px 80px" }}>
        {/* hero */}
        <div style={{ display: "flex", gap: 24, alignItems: "center", marginBottom: 36, flexWrap: "wrap" }}>
          <AppIcon app={app} size={80} />
          <div style={{ flex: 1, minWidth: 200 }}>
            <h1 style={{
              fontSize: 28, fontWeight: 800, margin: 0,
              fontFamily: "'Orbitron', sans-serif",
              letterSpacing: ".02em",
              background: `linear-gradient(135deg, ${T.cyan}, ${T.magenta})`,
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}>
              {app.name}
            </h1>
            <p style={{ color: T.textSec, fontSize: 14, margin: "10px 0 0", lineHeight: 1.6 }}>
              {app.shortDescription || app.summary || ""}
            </p>
          </div>
        </div>

        {/* actions */}
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 32 }}>
          {url ? (
            <a href={url} target="_blank" rel="noreferrer" style={{
              display: "inline-flex", alignItems: "center", gap: 10,
              padding: "14px 36px",
              background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`,
              border: `1px solid ${T.cyan}66`,
              color: T.cyan,
              fontFamily: "'Orbitron', sans-serif",
              fontWeight: 700, fontSize: 13, letterSpacing: ".1em",
              textTransform: "uppercase",
              borderRadius: 3, textDecoration: "none",
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
            ><span style={{ fontSize: 16 }}>↓</span> INSTALL</a>
          ) : (
            <div style={{
              padding: "14px 28px", background: T.surface,
              borderRadius: 3, fontSize: 13, fontWeight: 500,
              border: `1px solid ${T.border}`, color: T.textDim,
              fontFamily: "'JetBrains Mono', monospace",
            }}>Connect server to install</div>
          )}
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
        </div>

        {/* tags */}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 32 }}>
          {(app.categories || []).map((c) => <Badge key={c}>{c}</Badge>)}
          {app.isOpenSource && <Badge neon={T.green}>Open Source</Badge>}
          {!app.isOpenSource && <Badge neon={T.magenta}>HLSL</Badge>}
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
                backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
              }}>
                <div style={{
                  fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                  letterSpacing: ".14em", color: T.cyan, marginBottom: 16,
                  fontFamily: "'Orbitron', sans-serif",
                  textShadow: `0 0 6px ${T.accentGlow}`,
                  display: "flex", alignItems: "center", gap: 10,
                }}>
                  <span style={{ width: 16, height: 1, background: T.cyan, boxShadow: `0 0 4px ${T.cyan}` }} />
                  ABOUT
                </div>
                <div style={{ fontSize: 13, lineHeight: 1.8, color: T.textSec, whiteSpace: "pre-wrap" }}>
                  {app.description}
                </div>
              </div>
            )}
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{
              background: T.surface, borderRadius: T.radius,
              border: `1px solid ${T.border}`, overflow: "hidden",
              backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
            }}>
              <div style={{
                padding: "14px 20px", borderBottom: `1px solid ${T.border}`,
                fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                letterSpacing: ".14em", color: T.cyan,
                fontFamily: "'Orbitron', sans-serif",
                textShadow: `0 0 6px ${T.accentGlow}`,
                display: "flex", alignItems: "center", gap: 10,
              }}>
                <span style={{ width: 16, height: 1, background: T.cyan, boxShadow: `0 0 4px ${T.cyan}` }} />
                DETAILS
              </div>
              {rows.map(([label, val], i) => (
                <div key={label} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "flex-start",
                  gap: 12, padding: "12px 20px",
                  borderBottom: i < rows.length - 1 ? `1px solid ${T.borderLight}` : "none",
                  fontSize: 12,
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

            <div style={{
              padding: "14px 20px", background: T.surface,
              borderRadius: T.radiusSm, border: `1px solid ${T.border}`,
              backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
            }}>
              <span style={{
                display: "block", fontSize: 9, fontWeight: 700, textTransform: "uppercase",
                letterSpacing: ".12em", color: T.textDim, marginBottom: 8,
                fontFamily: "'Orbitron', sans-serif",
              }}>APP_ID</span>
              <code style={{
                fontSize: 10, color: T.cyan + "77", wordBreak: "break-all", lineHeight: 1.7,
                fontFamily: "'JetBrains Mono', monospace",
              }}>
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
        background: "rgba(7, 7, 13, 0.88)",
        backdropFilter: "blur(20px) saturate(1.4)",
        WebkitBackdropFilter: "blur(20px) saturate(1.4)",
        borderBottom: `1px solid ${T.cyan}18`,
      }}>
        <div style={{
          maxWidth: 1200, margin: "0 auto", padding: "12px 16px",
          display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
        }}>
          {/* Logo */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: "auto" }}>
            <img src={LOGO_URL} alt="Melusina" style={{
              width: 36, height: 36, borderRadius: 3,
              filter: `drop-shadow(0 0 8px ${T.cyan}88) drop-shadow(0 0 20px ${T.accentGlow})`,
              animation: "flicker 4s ease-in-out infinite",
            }} />
            <span style={{
              fontSize: 16, fontWeight: 800, letterSpacing: ".05em",
              fontFamily: "'Orbitron', sans-serif",
            }}>
              <span className="neon-text" style={{ animation: "flicker 4s ease-in-out infinite" }}>
                MELUSINA
              </span>
              <span style={{
                color: T.textDim, fontWeight: 400, marginLeft: 8, fontSize: 11,
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: ".12em", textTransform: "uppercase",
              }}>
                APP.MARKET
              </span>
            </span>
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
                background: "rgba(0,240,255,0.04)",
                border: `1px solid ${T.cyan}22`, borderRadius: 3, color: T.text,
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

          <HostBar host={host} setHost={setHost} />
        </div>
      </header>

      {/* categories */}
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "18px 16px 0" }}>
        <div className="cat-scroll" style={{
          display: "flex", gap: 8, overflowX: "auto", paddingBottom: 6,
          WebkitOverflowScrolling: "touch",
        }}>
          {categories.map((c) => {
            const active = category === c;
            return (
              <button key={c} onClick={() => setCategory(c)} style={{
                padding: "8px 20px", borderRadius: 2,
                border: `1px solid ${active ? T.cyan + "66" : T.cyan + "18"}`,
                background: active
                  ? `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}11)`
                  : "rgba(0,240,255,0.03)",
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
      <main style={{ maxWidth: 1200, margin: "0 auto", padding: "20px 16px 80px" }}>
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
                <AppCard app={app} onSelect={onSelect} host={host} />
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

      {/* bottom neon line */}
      <div style={{
        position: "fixed", bottom: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, transparent, ${T.cyan}44, ${T.magenta}44, transparent)`,
        pointerEvents: "none",
      }} />
    </>
  );
}

createRoot(document.getElementById("root")).render(<App />);
