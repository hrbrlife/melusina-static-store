import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { format } from "date-fns";
import "bootstrap/dist/css/bootstrap.min.css";
import data from "./apps.json";

const APP_INDEX_BASE = "https://hrbrlife.github.io/melusina-static-store";

const sanitizeHost = (host) => {
  if (!host) return "";
  const trimmed = host.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return `https://${trimmed}`.replace(/\/+$/, "");
  }
  return trimmed.replace(/\/+$/, "");
};

const formatDate = (value) => {
  if (!value) return "\u2014";
  const ts = Date.parse(value);
  if (Number.isNaN(ts)) return value;
  return format(ts, "MMM dd, yyyy");
};

const imageUrl = (imageId) => {
  if (!imageId) return null;
  return `${APP_INDEX_BASE}/images/${imageId}`;
};

const buildInstallUrl = (host, app) => {
  const cleanHost = sanitizeHost(host);
  if (!cleanHost || !app.packageId) return null;
  const pkgUrl = `${APP_INDEX_BASE}/packages/${app.packageId}`;
  return `${cleanHost}/install/${app.packageId}?url=${encodeURIComponent(pkgUrl)}`;
};

function App() {
  const [apps, setApps] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const [sandstormHost, setSandstormHost] = useState(
    localStorage.getItem("sandstormHost") || ""
  );

  useEffect(() => {
    const normalized = (data.apps || []).map((app) => ({
      ...app,
      _id: app.appId,
      categories: app.categories || [],
    }));
    setApps(normalized);
    if (normalized.length > 0) {
      setSelectedId(normalized[0].appId);
    }
  }, []);

  useEffect(() => {
    if (sandstormHost) {
      localStorage.setItem("sandstormHost", sandstormHost);
    }
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
        [app.name, app.shortDescription, app.appId, app.packageId, app.upstreamAuthor, app.author && app.author.name]
          .filter(Boolean)
          .some((field) => field.toLowerCase().includes(q));
      return matchesCategory && matchesQuery;
    });
  }, [apps, query, category]);

  return (
    <div className="container-fluid py-3" style={{ maxWidth: 1400 }}>
      <header className="mb-4 text-center">
        <h1 className="h3 mb-1" style={{ color: "#7a49a5" }}>Melusina App Market</h1>
        <p className="text-muted mb-3">
          Install any of the apps below with just one click.
        </p>
        <div className="row justify-content-center g-2 mb-3">
          <div className="col-auto">
            <input
              className="form-control"
              placeholder="Search apps..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{ minWidth: 200 }}
            />
          </div>
          <div className="col-auto">
            <select
              className="form-select"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              {categories.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
          <div className="col-auto">
            <input
              className="form-control"
              placeholder="Your Sandstorm host URL"
              value={sandstormHost}
              onChange={(e) => setSandstormHost(e.target.value)}
              style={{ minWidth: 260 }}
            />
          </div>
        </div>
        {!sandstormHost && (
          <div className="alert alert-info d-inline-block py-1 px-3 small">
            Enter your Sandstorm host URL above to enable one-click install
          </div>
        )}
      </header>

      <div className="row g-3">
        <div className="col-12 col-lg-5 col-xl-4">
          <div className="list-group" style={{ maxHeight: "80vh", overflowY: "auto" }}>
            {filtered.map((app) => (
              <button
                key={app.appId}
                className={`list-group-item list-group-item-action ${
                  selectedId === app.appId ? "active" : ""
                }`}
                onClick={() => setSelectedId(app.appId)}
              >
                <div className="d-flex align-items-center gap-2">
                  {app.imageId && (
                    <img
                      src={imageUrl(app.imageId)}
                      alt=""
                      style={{ width: 32, height: 32, objectFit: "contain" }}
                      onError={(e) => { e.target.style.display = "none"; }}
                    />
                  )}
                  <div className="flex-grow-1" style={{ minWidth: 0 }}>
                    <div className="d-flex justify-content-between">
                      <strong className="text-truncate">{app.name}</strong>
                      <small className="text-nowrap ms-2">{app.version || "\u2014"}</small>
                    </div>
                    <small className={`text-truncate d-block ${selectedId === app.appId ? "text-white-50" : "text-muted"}`}>
                      {app.shortDescription || ""}
                    </small>
                  </div>
                </div>
              </button>
            ))}
            {filtered.length === 0 && (
              <div className="list-group-item text-muted">No apps found.</div>
            )}
          </div>
          <div className="text-muted small mt-2 text-center">
            {filtered.length} app{filtered.length !== 1 ? "s" : ""}
          </div>
        </div>

        <div className="col-12 col-lg-7 col-xl-8">
          {selectedApp ? (
            <AppDetail app={selectedApp} sandstormHost={sandstormHost} />
          ) : (
            <div className="text-muted">Select an app to view details.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function AppDetail({ app, sandstormHost }) {
  const installUrl = buildInstallUrl(sandstormHost, app);

  return (
    <div className="card shadow-sm">
      <div className="card-body">
        <div className="d-flex gap-3 align-items-start mb-3">
          {app.imageId && (
            <img
              src={imageUrl(app.imageId)}
              alt={app.name}
              style={{ width: 80, height: 80, objectFit: "contain", borderRadius: 8 }}
              onError={(e) => { e.target.style.display = "none"; }}
            />
          )}
          <div className="flex-grow-1">
            <h2 className="h4 mb-1">{app.name}</h2>
            <p className="text-muted mb-1">{app.shortDescription}</p>
            <div className="d-flex flex-wrap gap-1 mb-2">
              {(app.categories || []).map((c) => (
                <span key={c} className="badge" style={{ backgroundColor: "#7a49a5" }}>{c}</span>
              ))}
            </div>
          </div>
          <div className="d-flex flex-column gap-1 text-end">
            {app.webLink && (
              <a href={app.webLink} target="_blank" rel="noreferrer" className="btn btn-outline-secondary btn-sm">
                Website
              </a>
            )}
            {app.codeLink && (
              <a href={app.codeLink} target="_blank" rel="noreferrer" className="btn btn-outline-secondary btn-sm">
                Source
              </a>
            )}
          </div>
        </div>

        {installUrl ? (
          <a
            className="btn btn-sm mb-3"
            href={installUrl}
            target="_blank"
            rel="noreferrer"
            style={{ backgroundColor: "#7a49a5", color: "white" }}
          >
            INSTALL &#9654;
          </a>
        ) : (
          <div className="text-muted small mb-3">
            {!sandstormHost
              ? "Enter your Sandstorm host URL to install"
              : "Package not available"}
          </div>
        )}

        <dl className="row mb-0 small">
          <dt className="col-sm-3">Version</dt>
          <dd className="col-sm-9">{app.version || "\u2014"}</dd>

          <dt className="col-sm-3">Version #</dt>
          <dd className="col-sm-9">{app.versionNumber != null ? app.versionNumber : "\u2014"}</dd>

          <dt className="col-sm-3">Author</dt>
          <dd className="col-sm-9">
            {app.author && app.author.name ? app.author.name : "\u2014"}
            {app.author && app.author.githubUsername && (
              <a href={`https://github.com/${app.author.githubUsername}`} className="ms-2" target="_blank" rel="noreferrer">
                GitHub
              </a>
            )}
          </dd>

          <dt className="col-sm-3">Upstream Author</dt>
          <dd className="col-sm-9">{app.upstreamAuthor || "\u2014"}</dd>

          <dt className="col-sm-3">Open Source</dt>
          <dd className="col-sm-9">{app.isOpenSource ? "Yes" : "No"}</dd>

          <dt className="col-sm-3">Published</dt>
          <dd className="col-sm-9">{formatDate(app.createdAt)}</dd>

          <dt className="col-sm-3">Package ID</dt>
          <dd className="col-sm-9"><code>{app.packageId}</code></dd>

          <dt className="col-sm-3">App ID</dt>
          <dd className="col-sm-9"><code className="text-break">{app.appId}</code></dd>
        </dl>
      </div>
    </div>
  );
}

const container = document.getElementById("root");
const root = createRoot(container);
root.render(<App />);
