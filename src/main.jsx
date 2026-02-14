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

.md-body h2{font-size:18px;font-weight:800;color:${T.text};margin:28px 0 12px;font-family:'Orbitron',sans-serif;letter-spacing:.02em}
.md-body h2:first-child{margin-top:0}
.md-body h3{font-size:15px;font-weight:700;color:${T.cyan};margin:24px 0 10px;font-family:'Orbitron',sans-serif;text-shadow:0 0 6px ${T.accentGlow}}
.md-body h4{font-size:13px;font-weight:700;color:${T.magenta};margin:20px 0 8px;font-family:'Orbitron',sans-serif}
.md-body p{font-size:13px;line-height:1.8;color:${T.textSec};margin:0 0 12px}
.md-body ul{margin:0 0 16px 0;padding-left:0;list-style:none}
.md-body ul li{font-size:13px;line-height:1.8;color:${T.textSec};padding-left:18px;position:relative;margin-bottom:4px}
.md-body ul li::before{content:'▸';position:absolute;left:0;color:${T.cyan};font-size:11px;text-shadow:0 0 4px ${T.accentGlow}}
.md-body code{background:${T.cyan}11;color:${T.cyan};padding:2px 6px;border-radius:2px;font-size:0.9em;font-family:'JetBrains Mono',monospace}
.md-body a{color:${T.cyan};border-bottom:1px solid ${T.cyan}33}
.md-body strong{color:${T.text};font-weight:600}

.review-card{padding:20px;background:${T.surface};border:1px solid ${T.border};border-radius:${T.radius}px;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);transition:border-color .2s}
.review-card:hover{border-color:${T.cyan}33}

@media(max-width:480px){.detail-tab{padding:12px 16px;font-size:10px;letter-spacing:.06em}}
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

/* ─── Simple Markdown ──────────────────────────────────────────────────────── */

function SimpleMarkdown({ text }) {
  if (!text) return null;
  const parseInline = (str) => {
    const parts = [];
    let rest = str, k = 0;
    while (rest.length > 0) {
      let m;
      if ((m = rest.match(/^\*\*(.+?)\*\*/))) {
        parts.push(<strong key={k++}>{m[1]}</strong>);
        rest = rest.slice(m[0].length);
      } else if ((m = rest.match(/^`(.+?)`/))) {
        parts.push(<code key={k++}>{m[1]}</code>);
        rest = rest.slice(m[0].length);
      } else if ((m = rest.match(/^\[(.+?)\]\((.+?)\)/))) {
        parts.push(<a key={k++} href={m[2]} target="_blank" rel="noreferrer">{m[1]}</a>);
        rest = rest.slice(m[0].length);
      } else {
        const nx = rest.slice(1).search(/\*\*|`|\[/);
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
    if (ln.startsWith('### ')) { els.push(<h4 key={k++}>{parseInline(ln.slice(4))}</h4>); i++; }
    else if (ln.startsWith('## ')) { els.push(<h3 key={k++}>{parseInline(ln.slice(3))}</h3>); i++; }
    else if (ln.startsWith('# ')) { els.push(<h2 key={k++}>{parseInline(ln.slice(2))}</h2>); i++; }
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

const APP_DOCS = {
  'qmg51xrjd1psztwd5pf48gqn9r4qak8vs3896zw4y2djhnpq523h': `# Getting Started with BLOOM Identity\n\nBLOOM Identity is a self-hosted KYC identity verification platform for Sandstorm.\n\n## Installation\n\n- Connect your Sandstorm server using the **CONNECT** button in the app market header\n- Click **INSTALL** to deploy BLOOM to your server\n- Create a new BLOOM grain from your Sandstorm dashboard\n\n## Admin Dashboard\n\nThe admin dashboard shows all active and completed verification cases. From here you can:\n\n- Create shareable verification links for respondents\n- Monitor verification status in real-time\n- Review completed cases with uploaded documents and facial captures\n- Approve or reject verification submissions\n\n## Verification Flow\n\nRespondents receive a link and complete these steps:\n\n- Accept Terms & Conditions\n- Upload a government-issued ID document\n- Complete live facial verification capture\n- Enter OTP confirmation code\n- Submit for admin review\n\n## Supported Document Types\n\n- Passport\n- Driver's License\n- National ID Card\n- Residence Permit\n\n## Privacy & Security\n\nAll data stays on your Sandstorm server. No documents or biometric data are sent to external APIs. The entire verification pipeline runs locally within your grain sandbox.`,

  'xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0': `# Getting Started with BotMother\n\nBotMother is a Telegram bot manager with message routing and chatroom support, running on Sandstorm.\n\n## Installation\n\n- Install BotMother from the Melusina App Market\n- Create a new BotMother grain on your Sandstorm server\n\n## Setting Up Your Bot\n\n- Create a bot via [BotFather](https://t.me/BotFather) on Telegram\n- Copy the bot token\n- Paste it into BotMother's configuration page\n- Your bot is now connected and routing messages through Sandstorm\n\n## Message Routing\n\nBotMother lets you define routing rules for incoming messages:\n\n- Route by command (e.g. /help, /start)\n- Route by keyword matching\n- Route by user group or chat ID\n- Set up auto-responses for common queries\n\n## Chatrooms\n\nCreate managed chatrooms that your bot moderates:\n\n- Set welcome messages\n- Configure moderation rules\n- Track message history within Sandstorm\n\n## Security\n\nAll message data stays on your Sandstorm server. Bot tokens are stored securely in the grain sandbox.`,

  'dwe1pv4ckrxjx3y45mjh166vxjmayqzu6zfg1x2rypy0zk0stcxh': `# Getting Started with Bureau Office Suite\n\nBureau is a multi-grain collaborative office suite for Sandstorm with four distinct tools.\n\n## Installation\n\n- Install Bureau from the Melusina App Market\n- When creating a new grain, choose the grain type: **Spreadsheet**, **Document**, **Diagram**, or **miniPaint**\n\n## Spreadsheet\n\n- Real-time multi-user editing via WebSocket\n- Cell styling, merged cells, comments\n- Column/row operations with undo/redo\n- Import/export: CSV, JSON, XLSX\n- Named version snapshots with restore\n\n## Document Editor\n\n- Built on TipTap with Yjs CRDT for conflict-free editing\n- Headings, lists, blockquotes, code blocks, tables\n- Real-time collaboration with presence indicators\n- Named version snapshots\n\n## Diagram Tool\n\n- Flowcharts, org charts, network diagrams\n- Shapes, connectors, text labels\n- Real-time sync and versioning\n- Export to image formats\n\n## miniPaint\n\n- Layer-based image editor\n- Filters: blur, sharpen, brightness, contrast\n- Drawing tools, crop, resize, rotate\n- Export: PNG, JPG, BMP, WebP\n\n## Collaboration & Permissions\n\n- **Viewer**: Read-only access\n- **Commenter**: Can add comments\n- **Editor**: Full editing access\n- **Admin**: Manage permissions and settings\n\nAll permissions are enforced server-side via Sandstorm's capability system.`,

  'wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h': `# Getting Started with Instasys Mail\n\nInstasys Mail is a native email client for Sandstorm, built with Go and HTMX.\n\n## Installation\n\n- Install Instasys Mail from the Melusina App Market\n- Create a new grain — each grain is an independent mailbox\n\n## Receiving Email\n\nEmail arrives via Sandstorm's built-in SMTP gateway and is stored locally in SQLite. No external mail server configuration needed.\n\n## Composing Messages\n\n- Rich compose form with To, CC, BCC fields\n- Reply, Reply All, and Forward support\n- Draft auto-save — resume editing anytime\n- File attachments with inline preview\n\n## Organizing Mail\n\n- Create custom folders\n- Star important messages\n- Move messages between folders\n- Bulk delete and archive\n- Full-text search across all messages\n\n## Sharing Access\n\nUse Sandstorm's sharing system to grant access:\n\n- **Viewer**: Read-only mailbox access\n- **Editor**: Can compose and manage messages\n- **Admin**: Full control including settings\n\n## Technical Architecture\n\n- **Backend**: Go with native Cap'n Proto RPC (no sandstorm-http-bridge)\n- **Frontend**: Server-side HTML + HTMX + WebSocket\n- **Storage**: SQLite with automatic migrations\n- **Updates**: Real-time WebSocket push for new mail`,

  'pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50': `# Getting Started with MiniGit\n\nMiniGit provides lightweight Git hosting with a web interface on Sandstorm.\n\n## Installation\n\n- Install MiniGit from the Melusina App Market\n- Create a new grain — each grain is a Git repository\n\n## Cloning & Pushing\n\nUse the Sandstorm API URL provided in your grain to clone and push:\n\n- \`git clone <grain-url>\`\n- \`git push origin main\`\n\nAuthentication is handled automatically by Sandstorm.\n\n## Web Interface\n\nBrowse your repository through the built-in GitWeb interface:\n\n- File tree navigation\n- Commit history and diffs\n- Search file contents\n- Branch and tag listing\n\n## Publishing Static Sites\n\nPush to the special **public** branch to publish static content at a Pearl URL:\n\n- \`git checkout -b public\`\n- Add your HTML/CSS/JS files\n- \`git push origin public\`\n\nYour site is now accessible via Sandstorm's Pearl URL system.\n\n## Permissions\n\n- Grant read or read/write access via Sandstorm sharing\n- Each grain is fully isolated from others`,

  'nn4ddmmdrs72caf25m0czd4ayk6qt0vx9ny7yzkygn962tkk08kh': `# Getting Started with Shell Tester\n\nShell Tester is a Melusina Shell Extension testing tool for Sandstorm.\n\n## Installation\n\n- Install Shell Tester from the Melusina App Market\n- Create a new grain to begin testing\n\n## What It Does\n\nShell Tester provides an interactive environment for testing Melusina Shell Extensions. You can:\n\n- Load and test shell extension packages\n- Verify extension APIs and hooks\n- Debug extension behavior in a sandboxed environment\n- Validate extension manifest files\n\n## Running Tests\n\n- Upload your extension package\n- Shell Tester automatically detects test suites\n- View test results with pass/fail indicators\n- Inspect logs and error output\n\n## For Extension Developers\n\n- Use Shell Tester during development to validate your extensions\n- Test against different Melusina Shell versions\n- Verify permissions and capability requirements`
};

const APP_FAQ = {
  _common: [
    { q: 'How do I install this app?', a: 'Click the **CONNECT** button in the header and enter your Sandstorm server URL. Then click the **INSTALL** button on the app detail page. The app will be deployed to your server automatically.' },
    { q: 'Is my data private?', a: 'Yes. All data stays on your Sandstorm server. There is no telemetry, analytics, or external data transmission. Each app grain is sandboxed and isolated.' },
    { q: 'How do I share access with others?', a: "Use Sandstorm's built-in sharing system. Click the sharing icon in your grain's top bar and generate a sharing link with the appropriate permission level (Viewer, Editor, or Admin)." },
    { q: 'How do I update to the latest version?', a: 'Updates appear automatically in your Sandstorm admin panel. You can also revisit the App Market and re-install to get the latest version.' },
    { q: 'How do I backup my data?', a: "Use Sandstorm's built-in grain backup feature. Go to your grain's top-bar menu and select 'Download Backup'. This creates a portable .zip of your grain that can be restored on any Sandstorm server." },
    { q: 'Can I run multiple instances?', a: 'Yes. Each Sandstorm grain is an independent instance with its own data. You can create as many grains as you need.' },
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
  'qmg51xrjd1psztwd5pf48gqn9r4qak8vs3896zw4y2djhnpq523h': [
    { q: 'What document types does BLOOM support?', a: 'BLOOM supports passports, driver\'s licenses, national ID cards, and residence permits. The document detection system automatically identifies the document type.' },
    { q: 'Does facial verification use external AI?', a: 'No. All AI processing runs locally within your Sandstorm grain. No images or biometric data leave your server.' },
    { q: 'Can respondents complete verification on mobile?', a: 'Yes. The verification flow is fully responsive and optimized for mobile browsers. Camera access for facial capture works on iOS and Android.' },
  ],
  'dwe1pv4ckrxjx3y45mjh166vxjmayqzu6zfg1x2rypy0zk0stcxh': [
    { q: 'Can multiple users edit a spreadsheet simultaneously?', a: 'Yes. Bureau uses WebSocket for real-time multi-user editing with presence indicators showing who else is viewing or editing.' },
    { q: 'What file formats can I import/export?', a: 'Spreadsheets support CSV, JSON, and XLSX. Documents export to HTML. Images export to PNG, JPG, BMP, and WebP.' },
    { q: 'How do snapshots work?', a: 'All grain types support named version snapshots. Save a snapshot with a name, browse your snapshot history, compare changes, and restore any previous version.' },
  ],
  'wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h': [
    { q: 'How does email delivery work?', a: 'Email arrives via Sandstorm\'s built-in SMTP gateway. Each grain has its own email address. No external mail server configuration is needed.' },
    { q: 'Can I use a custom domain for email?', a: 'Email addressing is managed by your Sandstorm server configuration. Contact your Sandstorm admin to set up custom domain routing.' },
  ],
  'pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50': [
    { q: 'How do I publish a static website?', a: 'Push your HTML/CSS/JS files to a branch named **public** in your MiniGit grain. Sandstorm will serve the contents at a Pearl URL.' },
    { q: 'What Git operations are supported?', a: 'All standard Git operations: clone, push, pull, branch, tag. Authentication is handled by Sandstorm\'s capability system.' },
  ],
};

const APP_REVIEWS = {
  'qmg51xrjd1psztwd5pf48gqn9r4qak8vs3896zw4y2djhnpq523h': [
    { author: 'ComplianceOps', rating: 5, date: '2026-01-28', title: 'Self-hosted KYC done right', text: 'We needed KYC that didn\'t send documents to third-party APIs. BLOOM runs entirely on our server. The admin review flow and facial verification are well-designed.' },
    { author: 'devops_sarah', rating: 4, date: '2026-01-15', title: 'Solid implementation', text: 'Clean setup, document verification and OTP work great. Would love webhook notifications when verifications complete. Looking forward to updates.' },
    { author: 'fintech_piotr', rating: 5, date: '2025-12-20', title: 'Perfect for our POC', text: 'Running this for our fintech proof-of-concept. Shareable verification links are ideal for customer onboarding. Privacy-first KYC is a huge differentiator.' },
    { author: 'sandstorm_user42', rating: 4, date: '2025-12-08', title: 'Great concept', text: 'Love the idea of self-hosted identity verification. The 8-step flow is comprehensive. UI could use dark mode but functionality is excellent.' },
  ],
  'xjdtxcy392qtrf317pyutxt2h5m022h291juzj1fs7023qsck3j0': [
    { author: 'bot_developer', rating: 4, date: '2026-01-20', title: 'Nice Telegram integration', text: 'Easy to connect my Telegram bot. Message routing rules are flexible. Chatroom management is a nice bonus.' },
    { author: 'community_mgr', rating: 5, date: '2026-01-05', title: 'Exactly what I needed', text: 'Managing our community bot through Sandstorm gives us full control. No more relying on third-party bot hosting services.' },
    { author: 'privacy_max', rating: 4, date: '2025-12-18', title: 'Self-hosted bot hosting', text: 'All messages stay on our server. Great for organizations that need to keep communications private. Routing is intuitive.' },
  ],
  'dwe1pv4ckrxjx3y45mjh166vxjmayqzu6zfg1x2rypy0zk0stcxh': [
    { author: 'office_admin', rating: 5, date: '2026-02-01', title: 'Incredible office suite', text: 'Bureau replaces Google Docs for our team. Real-time collaboration on spreadsheets works flawlessly. The snapshot feature is a lifesaver for version management.' },
    { author: 'designer_jay', rating: 4, date: '2026-01-22', title: 'miniPaint is a nice surprise', text: 'Didn\'t expect a full image editor bundled in. Layers, filters, and export work well. The diagram tool is great for quick flowcharts too.' },
    { author: 'data_analyst_k', rating: 5, date: '2026-01-10', title: 'Powerful spreadsheet', text: 'XLSX import/export, formula support, and real-time collab. Running it on our own server means no data leaks. The best self-hosted spreadsheet I\'ve used.' },
    { author: 'team_lead_r', rating: 4, date: '2025-12-30', title: 'Solid document editor', text: 'TipTap-based editor is responsive and handles formatting well. CRDT sync means no conflicts even with 5+ people editing simultaneously.' },
    { author: 'privacy_advocate', rating: 5, date: '2025-12-15', title: 'Finally, a private office suite', text: 'No Google, no Microsoft, no data mining. Bureau on Sandstorm gives our NGO everything we need without compromising our principles.' },
  ],
  'wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h': [
    { author: 'sysadmin_elena', rating: 4, date: '2026-01-18', title: 'Clean email client', text: 'Love that it uses native Cap\'n Proto instead of the HTTP bridge. Fast and lightweight. HTMX frontend is snappy. SQLite storage keeps things simple.' },
    { author: 'privacy_first', rating: 5, date: '2026-01-02', title: 'Email on my terms', text: 'Finally an email client that runs on MY server. No scanning, no ads, no tracking. Sandstorm\'s SMTP gateway makes setup painless.' },
    { author: 'developer_mike', rating: 4, date: '2025-12-22', title: 'Well-architected', text: 'The Go + HTMX stack is refreshingly simple. WebSocket for real-time updates is smooth. Would love to see CalDAV integration in the future.' },
  ],
  'pe3k6wapfczy7797n8xxu3qsn40sd1k4mvfmqv8kz2200dqavv50': [
    { author: 'indie_dev', rating: 5, date: '2026-01-25', title: 'Perfect for small projects', text: 'Host my personal repos without GitHub. The GitWeb interface is clean and the public branch feature for static sites is genius.' },
    { author: 'homelab_user', rating: 4, date: '2026-01-08', title: 'Lightweight and reliable', text: 'Running MiniGit for my homelab documentation repos. Dead simple, does exactly what it says. Push, pull, browse. No bloat.' },
    { author: 'educator_prof', rating: 5, date: '2025-12-28', title: 'Great for teaching', text: 'I give each student a MiniGit grain for their assignments. Sandstorm sharing makes access management trivial. The web viewer lets me review code without cloning.' },
  ],
  'nn4ddmmdrs72caf25m0czd4ayk6qt0vx9ny7yzkygn962tkk08kh': [
    { author: 'ext_developer', rating: 4, date: '2026-01-12', title: 'Essential for extension dev', text: 'If you\'re building Melusina Shell extensions, this is indispensable. Catches issues before deployment. Sandbox testing is well-implemented.' },
    { author: 'melusina_fan', rating: 5, date: '2025-12-25', title: 'Makes extension dev easy', text: 'Upload, test, iterate. Shell Tester makes the feedback loop tight. Log inspection is particularly useful for debugging.' },
  ],
};

function getAppFAQ(app) {
  const specific = APP_FAQ[app.appId] || [];
  const license = app.isOpenSource ? APP_FAQ._openSource : APP_FAQ._hlsl;
  return [...specific, ...license, ...APP_FAQ._common];
}

function getAppReviews(app) {
  return APP_REVIEWS[app.appId] || [];
}

function getAvgRating(reviews) {
  if (!reviews.length) return 0;
  return reviews.reduce((s, r) => s + r.rating, 0) / reviews.length;
}

/* ─── Detail Page ──────────────────────────────────────────────────────────── */

function DetailPage({ app, host, onClose }) {
  const url = installUrl(host, app);
  const [tab, setTab] = useState('overview');
  const [openFaq, setOpenFaq] = useState(null);

  const reviews = getAppReviews(app);
  const avgRating = getAvgRating(reviews);
  const faq = getAppFAQ(app);
  const docs = APP_DOCS[app.appId] || '';

  useEffect(() => {
    const h = (e) => e.key === "Escape" && onClose();
    window.scrollTo(0, 0);
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  useEffect(() => { setTab('overview'); setOpenFaq(null); }, [app.appId]);

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
    { id: 'docs', label: 'Documentation' },
    { id: 'faq', label: `FAQ (${faq.length})` },
    { id: 'reviews', label: `Reviews (${reviews.length})` },
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
      <ScreenshotGallery screenshots={app.screenshots} appId={app.appId} />
      <div className="detail-grid">
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {app.description && (
            <div style={{
              padding: 24, background: T.surface,
              borderRadius: T.radius, border: `1px solid ${T.border}`,
              backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
            }}>
              <SectionHeader>About</SectionHeader>
              <SimpleMarkdown text={app.description} />
            </div>
          )}
          {/* Quick stats */}
          {reviews.length > 0 && (
            <div style={{
              padding: 20, background: T.surface,
              borderRadius: T.radius, border: `1px solid ${T.border}`,
              backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
              display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 28, fontWeight: 800, color: T.text, fontFamily: "'Orbitron', sans-serif" }}>
                  {avgRating.toFixed(1)}
                </span>
                <div>
                  <StarRating rating={avgRating} size={16} />
                  <div style={{ fontSize: 11, color: T.textDim, marginTop: 4, fontFamily: "'JetBrains Mono', monospace" }}>
                    {reviews.length} review{reviews.length !== 1 ? 's' : ''}
                  </div>
                </div>
              </div>
              <button onClick={() => setTab('reviews')} {...renderBtnStyle(T.yellow)}>
                Read Reviews →
              </button>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* License / Pricing Card */}
          <div style={{
            background: T.surface, borderRadius: T.radius,
            border: `1px solid ${app.isOpenSource ? T.green + '33' : T.magenta + '33'}`,
            overflow: "hidden",
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <div style={{
              padding: "14px 20px", borderBottom: `1px solid ${T.borderLight}`,
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <SectionHeader color={app.isOpenSource ? T.green : T.magenta}>License & Pricing</SectionHeader>
            </div>
            <div style={{ padding: 20 }}>
              <div style={{
                display: "flex", alignItems: "center", gap: 10, marginBottom: 14,
              }}>
                <span style={{
                  fontSize: 20, width: 36, height: 36, borderRadius: 3,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: app.isOpenSource ? T.green + '15' : T.magenta + '15',
                  border: `1px solid ${app.isOpenSource ? T.green + '33' : T.magenta + '33'}`,
                }}>{app.isOpenSource ? '🔓' : '🔐'}</span>
                <div>
                  <div style={{
                    fontSize: 14, fontWeight: 700, color: app.isOpenSource ? T.green : T.magenta,
                    fontFamily: "'Orbitron', sans-serif",
                    textShadow: `0 0 6px ${app.isOpenSource ? T.greenGlow : T.magentaGlow}`,
                  }}>{app.isOpenSource ? 'Open Source' : 'HLSL License'}</div>
                  <div style={{ fontSize: 11, color: T.textDim, marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                    Self-hosted · No subscription
                  </div>
                </div>
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, color: T.text, fontFamily: "'Orbitron', sans-serif", marginBottom: 8 }}>
                FREE
              </div>
              <div style={{ fontSize: 12, lineHeight: 1.7, color: T.textSec, marginBottom: 14 }}>
                {app.isOpenSource
                  ? 'This app is free and open source. You can use, modify, and redistribute it under the terms of its license.'
                  : 'Free to install and use on your own Sandstorm server. Source code is available for auditing. Automatically converts to AGPLv3 after 3 years.'}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 11, color: T.textSec }}>
                {[
                  '✓ Self-hosted on your server',
                  '✓ No usage fees or limits',
                  '✓ Full data ownership',
                  app.isOpenSource ? '✓ Fork and modify freely' : '✓ Source-available for audit',
                  app.isOpenSource ? '✓ Community contributions welcome' : '✓ Converts to AGPLv3 after 3y',
                ].map((item, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ color: app.isOpenSource ? T.green : T.magenta, fontFamily: "'JetBrains Mono', monospace" }}>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Details Card */}
          <div style={{
            background: T.surface, borderRadius: T.radius,
            border: `1px solid ${T.border}`, overflow: "hidden",
            backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
          }}>
            <div style={{ padding: "14px 20px", borderBottom: `1px solid ${T.border}` }}>
              <SectionHeader>Details</SectionHeader>
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

          {/* App ID Card */}
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
    </>
  );

  /* ---- DOCS TAB ---- */
  const DocsTab = () => (
    <div style={{
      padding: 28, background: T.surface,
      borderRadius: T.radius, border: `1px solid ${T.border}`,
      backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
      maxWidth: 780,
    }}>
      {docs ? (
        <SimpleMarkdown text={docs} />
      ) : (
        <div style={{ textAlign: "center", padding: "60px 20px" }}>
          <div style={{ fontSize: 36, marginBottom: 16, opacity: 0.3 }}>📄</div>
          <p style={{ color: T.textDim, fontSize: 14, fontFamily: "'JetBrains Mono', monospace" }}>
            Documentation coming soon
          </p>
          {app.codeLink && (
            <a href={app.codeLink} target="_blank" rel="noreferrer" style={{
              display: "inline-block", marginTop: 16, fontSize: 12, padding: "10px 20px",
              border: `1px solid ${T.cyan}33`, borderRadius: 3,
              fontFamily: "'JetBrains Mono', monospace",
            }}>View README on GitHub →</a>
          )}
        </div>
      )}
    </div>
  );

  /* ---- FAQ TAB ---- */
  const FAQTab = () => (
    <div style={{ maxWidth: 780 }}>
      <SectionHeader>Frequently Asked Questions</SectionHeader>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 16 }}>
        {faq.map((item, i) => (
          <div key={i} className="faq-item" style={{
            border: `1px solid ${openFaq === i ? T.cyan + '33' : T.border}`,
            borderRadius: T.radius, overflow: "hidden", transition: "border-color .2s",
          }}>
            <button onClick={() => setOpenFaq(openFaq === i ? null : i)} style={{
              width: "100%", textAlign: "left",
              padding: "16px 20px", cursor: "pointer",
              display: "flex", justifyContent: "space-between", alignItems: "center",
              gap: 12, fontSize: 13, fontWeight: 600, color: openFaq === i ? T.cyan : T.text,
              background: T.surface, border: "none", transition: "all .2s",
              fontFamily: "inherit",
            }}>
              <span>{item.q}</span>
              <span style={{
                fontSize: 16, color: T.cyan, transition: "transform .2s",
                transform: openFaq === i ? 'rotate(45deg)' : 'none',
                flexShrink: 0, fontFamily: "'JetBrains Mono', monospace",
                textShadow: `0 0 4px ${T.accentGlow}`,
              }}>+</span>
            </button>
            {openFaq === i && (
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
        ))}
      </div>
    </div>
  );

  /* ---- REVIEWS TAB ---- */
  const ReviewsTab = () => (
    <div style={{ maxWidth: 780 }}>
      {/* Rating summary */}
      {reviews.length > 0 && (
        <div style={{
          display: "flex", gap: 32, alignItems: "center", flexWrap: "wrap",
          marginBottom: 28, padding: 24, background: T.surface,
          borderRadius: T.radius, border: `1px solid ${T.border}`,
          backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)",
        }}>
          <div style={{ textAlign: "center" }}>
            <div style={{
              fontSize: 48, fontWeight: 900, color: T.text,
              fontFamily: "'Orbitron', sans-serif",
              lineHeight: 1,
              textShadow: `0 0 20px ${T.accentGlow}`,
            }}>{avgRating.toFixed(1)}</div>
            <StarRating rating={avgRating} size={18} />
            <div style={{ fontSize: 11, color: T.textDim, marginTop: 6, fontFamily: "'JetBrains Mono', monospace" }}>
              {reviews.length} rating{reviews.length !== 1 ? 's' : ''}
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            {[5,4,3,2,1].map(star => {
              const count = reviews.filter(r => r.rating === star).length;
              const pct = reviews.length ? (count / reviews.length) * 100 : 0;
              return (
                <div key={star} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 11, color: T.textDim, width: 14, textAlign: "right", fontFamily: "'JetBrains Mono', monospace" }}>{star}</span>
                  <span style={{ fontSize: 11, color: T.yellow }}>★</span>
                  <div style={{ flex: 1, height: 6, background: T.bgAlt, borderRadius: 3, overflow: "hidden" }}>
                    <div style={{
                      width: `${pct}%`, height: "100%",
                      background: `linear-gradient(90deg, ${T.cyan}, ${T.yellow})`,
                      borderRadius: 3, transition: "width .3s",
                      boxShadow: pct > 0 ? `0 0 6px ${T.cyan}44` : 'none',
                    }} />
                  </div>
                  <span style={{ fontSize: 10, color: T.textDim, width: 20, fontFamily: "'JetBrains Mono', monospace" }}>{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Individual reviews */}
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {reviews.length === 0 ? (
          <div style={{ textAlign: "center", padding: "60px 20px" }}>
            <div style={{ fontSize: 36, marginBottom: 16, opacity: 0.3 }}>💬</div>
            <p style={{ color: T.textDim, fontSize: 14, fontFamily: "'JetBrains Mono', monospace" }}>
              No reviews yet. Be the first!
            </p>
          </div>
        ) : reviews.map((review, i) => (
          <div key={i} className="review-card" style={{ animation: `fadeUp .3s ease-out ${i * 0.05}s both` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 10 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{
                  width: 32, height: 32, borderRadius: 3,
                  background: `linear-gradient(135deg, ${T.cyan}22, ${T.magenta}22)`,
                  border: `1px solid ${T.cyan}33`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 13, fontWeight: 700, color: T.cyan,
                  fontFamily: "'Orbitron', sans-serif",
                  textShadow: `0 0 6px ${T.accentGlow}`,
                }}>{review.author[0].toUpperCase()}</div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: T.text,
                    fontFamily: "'JetBrains Mono', monospace" }}>{review.author}</div>
                  <div style={{ fontSize: 10, color: T.textDim }}>{review.date}</div>
                </div>
              </div>
              <StarRating rating={review.rating} size={12} />
            </div>
            {review.title && (
              <div style={{ fontSize: 13, fontWeight: 700, color: T.text, marginBottom: 6 }}>
                {review.title}
              </div>
            )}
            <div style={{ fontSize: 13, lineHeight: 1.7, color: T.textSec }}>
              {review.text}
            </div>
          </div>
        ))}
      </div>
    </div>
  );

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
          <button onClick={onClose} {...renderBtnStyle(T.cyan)}>← BACK</button>
          <span style={{
            fontSize: 14, fontWeight: 700, color: T.text,
            fontFamily: "'Orbitron', sans-serif",
            letterSpacing: ".03em",
          }}>{app.name}</span>
        </div>
      </div>

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "32px 20px 80px" }}>
        {/* hero */}
        <div style={{ display: "flex", gap: 24, alignItems: "center", marginBottom: 28, flexWrap: "wrap" }}>
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
            <p style={{ color: T.textSec, fontSize: 14, margin: "8px 0 0", lineHeight: 1.6 }}>
              {app.shortDescription || app.summary || ""}
            </p>
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
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 24 }}>
          {(app.categories || []).map((c) => <Badge key={c}>{c}</Badge>)}
          {app.isOpenSource && <Badge neon={T.green}>Open Source</Badge>}
          {!app.isOpenSource && <Badge neon={T.magenta}>HLSL</Badge>}
        </div>

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
          {tab === 'docs' && <DocsTab />}
          {tab === 'faq' && <FAQTab />}
          {tab === 'reviews' && <ReviewsTab />}
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
