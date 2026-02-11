import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { format } from "date-fns";
import "bootstrap/dist/css/bootstrap.min.css";
import data from "./apps.json";

const DEFAULT_HOST = "https://alpha.sandstorm.io";

const sanitizeHost = (host) => {
  if (!host) return DEFAULT_HOST;
  const trimmed = host.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return `https://${trimmed}`.replace(/\/+$/, "");
  }
  return trimmed.replace(/\/+$/, "");
};

const latestVersion = (app) => {
  if (!app.versions || app.versions.length === 0) return null;
  return [...app.versions].sort((a, b) => {
    const da = Date.parse(a.createdAt || 0);
    const db = Date.parse(b.createdAt || 0);
    return db - da;
  })[0];
};

function App() {
  const [apps, setApps] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const [sandstormHost, setSandstormHost] = useState(
    sanitizeHost(localStorage.getItem("sandstormHost") || DEFAULT_HOST)
  );
  const [verification, setVerification] = useState({});

  useEffect(() => {
    const normalized = (data.apps || []).map((app) => ({
      ...app,
      appId: app.appId || app.id,
      categories: app.categories || (app.category ? [app.category] : []),
    }));
    setApps(normalized);
    if (normalized.length > 0) {
      setSelectedId(normalized[0].appId);
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("sandstormHost", sandstormHost);
  }, [sandstormHost]);

  const categories = useMemo(() => {
    const set = new Set();
    apps.forEach((app) => (app.categories || []).forEach((c) => set.add(c)));
    return ["All", ...Array.from(set).sort()];
  }, [apps]);

  const selectedApp = useMemo(
    () => apps.find((a) => a.appId === selectedId),
    [apps, selectedId]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return apps.filter((app) => {
      const matchesCategory =
        category === "All" ||
        (app.categories || []).some((c) => c.toLowerCase() === category.toLowerCase());
      const matchesQuery =
        !q ||
        [app.name, app.summary, app.description, app.appId, app.packageId]
          .filter(Boolean)
          .some((field) => field.toLowerCase().includes(q));
      return matchesCategory && matchesQuery;
    });
  }, [apps, query, category]);

  const setVerificationStatus = (pkgId, status) => {
    setVerification((prev) => ({ ...prev, [pkgId]: status }));
  };

  return (
    <div className="container py-4">
      <header className="mb-4">
        <div className="d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-3">
          <div>
            <h1 className="h3 mb-0">Static Sandstorm App Market</h1>
            <small className="text-muted">
              Self-published apps with Sandstorm-compatible metadata
            </small>
          </div>
          <div className="d-flex gap-2 flex-wrap w-100 w-lg-auto">
            <input
              className="form-control"
              placeholder="Search apps"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              className="form-select"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <input
              className="form-control"
              placeholder="Sandstorm host (https://your.host)"
              value={sandstormHost}
              onChange={(e) => setSandstormHost(sanitizeHost(e.target.value))}
            />
          </div>
        </div>
      </header>

      <div className="row g-3">
        <div className="col-12 col-lg-5 col-xl-4">
          <div className="list-group">
            {filtered.map((app) => {
              const latest = latestVersion(app);
              return (
                <button
                  key={app.appId}
                  className={`list-group-item list-group-item-action ${
                    selectedId === app.appId ? "active" : ""
                  }`}
                  onClick={() => setSelectedId(app.appId)}
                >
                  <div className="d-flex w-100 justify-content-between">
                    <h5 className="mb-1">{app.name}</h5>
                    <small>{(latest && latest.number) || "—"}</small>
                  </div>
                  <p className="mb-1 text-truncate">{app.summary}</p>
                  <small>
                    {(app.categories || []).join(", ") || "Uncategorized"}
                  </small>
                </button>
              );
            })}
            {filtered.length === 0 && (
              <div className="list-group-item text-muted">No apps found.</div>
            )}
          </div>
        </div>

        <div className="col-12 col-lg-7 col-xl-8">
          {selectedApp ? (
            <AppDetail
              app={selectedApp}
              sandstormHost={sandstormHost}
              verification={verification}
              setVerificationStatus={setVerificationStatus}
            />
          ) : (
            <div className="text-muted">Select an app to view details.</div>
          )}
        </div>
      </div>
    </div>
  );
}

const buildInstallUrl = (host, version, app) => {
  const cleanHost = sanitizeHost(host);
  const pkgId = version.packageId || app.packageId;
  const download = version.downloadUrl || app.downloadUrl;
  if (!pkgId || !download) return null;
  return `${cleanHost}/install/${pkgId}?url=${encodeURIComponent(download)}`;
};

const formatDate = (value) => {
  if (!value) return "—";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return value;
  return format(ts, "yyyy-MM-dd");
};

async function verifySha256(url, expected) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const buffer = await resp.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  return hashHex === expected.toLowerCase();
}

function AppDetail({ app, sandstormHost, verification, setVerificationStatus }) {
  const latest = latestVersion(app);

  return (
    <div className="card shadow-sm">
      <div className="card-body">
        <div className="d-flex justify-content-between align-items-start gap-2">
          <div>
            <h2 className="h4">{app.name}</h2>
            <p className="text-muted mb-1">
              {app.author?.name || "Unknown author"}
              {app.upstreamAuthor ? ` • Upstream: ${app.upstreamAuthor}` : ""}
            </p>
            <p className="small text-muted">
              App ID: <code>{app.appId}</code>
            </p>
          </div>
          {app.imageId && (
            <span className="badge bg-secondary">{app.imageId}</span>
          )}
        </div>

        {app.summary && <p className="fw-semibold mt-2">{app.summary}</p>}

        <div className="mb-3">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{app.description || ""}</ReactMarkdown>
        </div>

        <dl className="row">
          <dt className="col-sm-3">Categories</dt>
          <dd className="col-sm-9">{(app.categories || []).join(", ") || "—"}</dd>

          <dt className="col-sm-3">License</dt>
          <dd className="col-sm-9">{app.license || "—"}</dd>

          <dt className="col-sm-3">Homepage</dt>
          <dd className="col-sm-9">
            {app.webLink ? <a href={app.webLink}>{app.webLink}</a> : "—"}
          </dd>

          <dt className="col-sm-3">Source</dt>
          <dd className="col-sm-9">
            {app.codeLink ? <a href={app.codeLink}>{app.codeLink}</a> : "—"}
          </dd>

          <dt className="col-sm-3">Report Issues</dt>
          <dd className="col-sm-9">
            {app.bugReportLink ? <a href={app.bugReportLink}>{app.bugReportLink}</a> : "—"}
          </dd>

          <dt className="col-sm-3">Updated</dt>
          <dd className="col-sm-9">{formatDate(app.updatedAt)}</dd>
        </dl>

        <h5 className="mt-4">Versions</h5>
        <div className="table-responsive">
          <table className="table align-middle">
            <thead>
              <tr>
                <th>Version</th>
                <th>Released</th>
                <th>Install</th>
                <th>SHA-256</th>
                <th>Verify</th>
              </tr>
            </thead>
            <tbody>
              {(app.versions || []).map((v) => {
                const installUrl = buildInstallUrl(sandstormHost, v, app);
                const status = verification[v.packageId] || null;
                return (
                  <tr key={`${v.packageId}-${v.number}`}>
                    <td>
                      <div className="fw-semibold">{v.number}</div>
                      {v.changelog && (
                        <small className="text-muted">{v.changelog}</small>
                      )}
                    </td>
                    <td>{formatDate(v.createdAt)}</td>
                    <td>
                      {installUrl ? (
                        <a className="btn btn-sm btn-primary" href={installUrl}>
                          Install
                        </a>
                      ) : (
                        <span className="text-muted">Missing package URL</span>
                      )}
                    </td>
                    <td>
                      {v.sha256 ? (
                        <code className="text-break d-block">{v.sha256}</code>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td>
                      {v.sha256 && v.downloadUrl ? (
                        <button
                          className="btn btn-sm btn-outline-secondary"
                          disabled={status === "pending"}
                          onClick={async () => {
                            setVerificationStatus(v.packageId, "pending");
                            try {
                              const ok = await verifySha256(v.downloadUrl, v.sha256);
                              setVerificationStatus(v.packageId, ok ? "ok" : "fail");
                            } catch (_err) {
                              setVerificationStatus(v.packageId, "fail");
                            }
                          }}
                        >
                          {status === "pending"
                            ? "Verifying..."
                            : status === "ok"
                            ? "Verified ✓"
                            : status === "fail"
                            ? "Failed ✗"
                            : "Verify"}
                        </button>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {app.screenshots && app.screenshots.length > 0 && (
          <>
            <h5 className="mt-4">Screenshots</h5>
            <div className="d-flex flex-wrap gap-2">
              {app.screenshots.map((shot) => (
                <span key={shot} className="badge bg-secondary text-wrap">
                  {shot}
                </span>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

const container = document.getElementById("root");
const root = createRoot(container);
root.render(<App />);
