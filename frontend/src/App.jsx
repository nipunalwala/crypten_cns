import React, { useEffect, useState, useMemo } from "react";
import { api } from "./api.js";

const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export default function App() {
  const [fixtures, setFixtures] = useState(null);
  const [path, setPath] = useState("");
  const [runExternal, setRunExternal] = useState(true);
  const [reclone, setReclone] = useState(false);
  const isLink = /^https?:\/\//i.test(path.trim());
  const [scanId, setScanId] = useState(null);
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [cweFilter, setCweFilter] = useState(null);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    api.fixtures().then((f) => {
      setFixtures(f);
      setPath(f.vulnerable);
    }).catch((e) => setError(e.message));
  }, []);

  async function runScan() {
    setError("");
    setBusy(true);
    setSelected(null);
    try {
      const { scan_id } = await api.createScan(path.trim(), runExternal, isLink && reclone);
      setScanId(scan_id);
      setData(await api.scan(scan_id));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    if (scanId) setData(await api.scan(scanId));
  }

  const findings = data?.findings ?? [];
  const inScope = findings.filter((f) => f.in_scope);
  const cwes = useMemo(
    () => [...new Set(inScope.map((f) => f.cwe_id))].sort(),
    [inScope]
  );
  const shown = cweFilter ? inScope.filter((f) => f.cwe_id === cweFilter) : inScope;

  const counts = findings.reduce(
    (acc, f) => {
      if (f.severity in acc) acc[f.severity] += 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  );
  const exploited = findings.filter((f) => f.verification === "EXPLOITED").length;

  return (
    <div className="app">
      <header className="masthead">
        <div>
          <div className="wordmark">cryp<b>Ten</b></div>
          <div className="tagline">
            Finds and proves insecure credential handling in small Python web apps,
            then patches it. Detect &rarr; verify in a sandbox &rarr; fix.
          </div>
        </div>
      </header>

      <div className="launcher">
        <input
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          spellCheck={false}
          aria-label="Target folder or repository link"
          placeholder="C:\path\to\app  or  https://github.com/owner/repo"
        />
        {fixtures && (
          <>
            <button onPointerDown={keepFocus} onMouseDown={keepFocus} onClick={() => setPath(fixtures.vulnerable)}>vulnerable fixture</button>
            <button onPointerDown={keepFocus} onMouseDown={keepFocus} onClick={() => setPath(fixtures.secure)}>secure fixture</button>
          </>
        )}
        <label>
          <input type="checkbox" checked={runExternal} onChange={(e) => setRunExternal(e.target.checked)} />
          external scanners
        </label>
        <label hidden={!isLink} title="Discard the copy in lab/ and clone again. Leave off to rescan a copy you've patched.">
          <input type="checkbox" checked={reclone} onChange={(e) => setReclone(e.target.checked)} />
          fresh clone
        </label>
        <button className="btn-primary" onClick={runScan} disabled={busy || !path}>
          {busy ? (isLink ? "cloning and scanning…" : "scanning…") : "Run scan"}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {data && (
        <>
          <div className="summary">
            <Cell n={inScope.length} cap="in-scope findings" />
            <Cell n={counts.CRITICAL} cap="critical" />
            <Cell n={counts.HIGH} cap="high" />
            <Cell n={exploited} cap="exploited" />
          </div>
          <ScannerLine scanners={JSON.parse(data.scan.scanners_json)} />
          {scanId && (
            <div className="reports">
              export report:
              <a href={api.reportUrl(scanId, "html")} target="_blank" rel="noreferrer">HTML</a>
              <a href={api.reportUrl(scanId, "json")} target="_blank" rel="noreferrer">JSON</a>
              <a href={api.reportUrl(scanId, "csv")} target="_blank" rel="noreferrer">CSV</a>
            </div>
          )}

          <div className="filters" style={{ marginTop: 20 }}>
            <button className="chip" aria-pressed={cweFilter === null} onClick={() => setCweFilter(null)}>
              all
            </button>
            {cwes.map((c) => (
              <button key={c} className="chip" aria-pressed={cweFilter === c} onClick={() => setCweFilter(c)}>
                {c}
              </button>
            ))}
          </div>

          {shown.length === 0 ? (
            <div className="empty">No in-scope credential weaknesses. This target is clean.</div>
          ) : (
            <FindingsTable
              findings={[...shown].sort((a, b) => b.priority - a.priority)}
              selectedId={selected?.id}
              onSelect={setSelected}
            />
          )}
        </>
      )}

      {!data && !error && <div className="empty">Pick a target and run a scan.</div>}

      {selected && (
        <DetailPanel
          finding={selected}
          onClose={() => setSelected(null)}
          onChanged={async () => {
            await refresh();
          }}
          setSelected={setSelected}
        />
      )}
    </div>
  );
}

// Stops a tap on a nearby control from taking focus off the path field, so a
// phone keyboard stays up while the user picks options.
function keepFocus(e) {
  e.preventDefault();
}

function Cell({ n, cap }) {
  return (
    <div className="cell">
      <div className="num">{n}</div>
      <div className="cap">{cap}</div>
    </div>
  );
}

function ScannerLine({ scanners }) {
  return (
    <div className="scanners">
      scanners:{" "}
      {scanners.map((s, i) => (
        <span key={s.name}>
          <span className={s.ran ? "ran" : "skip"}>{s.name}</span>
          {s.note ? ` (${s.note})` : ""}
          {i < scanners.length - 1 ? " · " : ""}
        </span>
      ))}
    </div>
  );
}

function FindingsTable({ findings, selectedId, onSelect }) {
  return (
    <table className="findings">
      <thead>
        <tr>
          <th>Sev</th>
          <th>Weakness</th>
          <th className="hide-sm">Location &amp; evidence</th>
          <th className="hide-sm">Found by</th>
          <th>Verdict</th>
          <th>Prio</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr
            key={f.id}
            aria-selected={f.id === selectedId}
            onClick={() => onSelect(f)}
          >
            <td><span className={`sev ${f.severity.toLowerCase()}`}>{f.severity}</span></td>
            <td>
              <span className="cwe-ref">{f.cwe_id}</span>
              <div className="cwe-title">{f.title}</div>
            </td>
            <td className="hide-sm">
              <span className="loc">{f.file_path}:{f.line}</span>
              <code className="ev">{f.evidence}</code>
            </td>
            <td className="hide-sm"><span className="scanner-tags">{f.scanners}</span></td>
            <td><Stamp verdict={f.verification} /></td>
            <td className="prio">{f.priority.toFixed(1)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Stamp({ verdict }) {
  return <span className={`stamp ${verdict.toLowerCase()}`}>{verdict.replace("_", " ")}</span>;
}

function DetailPanel({ finding, onClose, onChanged, setSelected }) {
  const [verifying, setVerifying] = useState(false);
  const [verdict, setVerdict] = useState(null);
  const [patch, setPatch] = useState(null);
  const [applied, setApplied] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    setVerdict(null);
    setPatch(null);
    setApplied(null);
    setErr("");
    api.patch(finding.id).then(setPatch).catch(() => setPatch({ available: false }));
  }, [finding.id]);

  async function doVerify() {
    setVerifying(true);
    setErr("");
    try {
      const v = await api.verify(finding.id);
      setVerdict(v);
      await onChanged();
      setSelected({ ...finding, verification: v.result });
    } catch (e) {
      setErr(e.message);
    } finally {
      setVerifying(false);
    }
  }

  async function doApply() {
    setErr("");
    try {
      const res = await api.applyPatch(finding.id);
      setApplied(res);
      await onChanged();
    } catch (e) {
      setErr(e.message);
    }
  }

  return (
    <aside className="detail" role="dialog" aria-label={`${finding.cwe_id} detail`}>
      <button className="close" onClick={onClose}>close</button>
      <h2>{finding.cwe_id}</h2>
      <div className="body-text" style={{ color: "var(--muted)" }}>{finding.title}</div>

      <section>
        <h3>Location</h3>
        <div className="loc">{finding.file_path}:{finding.line}</div>
        <pre className="artifact" style={{ marginTop: 8 }}>{finding.evidence}</pre>
        <div style={{ marginTop: 8, fontSize: "0.8rem", color: "var(--muted)" }}>
          found by {finding.scanners} · priority {finding.priority.toFixed(1)} ({finding.priority_reasons})
        </div>
      </section>

      <section>
        <h3>Verification</h3>
        <div className="actions">
          <button className="btn-primary" onClick={doVerify} disabled={verifying}>
            {verifying ? "running sandbox…" : "Run proof of concept"}
          </button>
          <Stamp verdict={verdict?.result ?? finding.verification} />
        </div>
        {verdict && (
          <div className="verdict-box">
            <div className="body-text">{verdict.summary}</div>
            <div className="detail-row">method: {verdict.method}</div>
            {Object.entries(verdict.details || {}).map(([k, v]) => (
              <div className="detail-row" key={k}>{k}: {JSON.stringify(v)}</div>
            ))}
          </div>
        )}
      </section>

      <section>
        <h3>Remediation</h3>
        {patch === null && <div className="spin">loading patch…</div>}
        {patch && !patch.available && (
          <div className="body-text" style={{ color: "var(--muted)" }}>No automatic patch for this finding.</div>
        )}
        {patch && patch.available && (
          <>
            <div className="body-text" style={{ fontWeight: 600 }}>{patch.title}</div>
            <div className="body-text" style={{ margin: "6px 0 10px", color: "var(--muted)" }}>{patch.rationale}</div>
            <Diff text={patch.diff} />
            {patch.artifact && (
              <>
                <h3 style={{ marginTop: 16 }}>Rehash-on-login migration</h3>
                <pre className="artifact">{patch.artifact}</pre>
              </>
            )}
            <div className="actions">
              <button onClick={doApply} disabled={!!applied}>
                {applied ? `applied · backup ${applied.backup}` : "Apply patch (writes .bak)"}
              </button>
            </div>
          </>
        )}
      </section>

      {err && <div className="error">{err}</div>}
    </aside>
  );
}

function Diff({ text }) {
  return (
    <pre className="diff">
      {text.split("\n").map((line, i) => {
        let cls = "";
        if (line.startsWith("+") && !line.startsWith("+++")) cls = "add";
        else if (line.startsWith("-") && !line.startsWith("---")) cls = "del";
        return <div key={i} className={cls}>{line || " "}</div>;
      })}
    </pre>
  );
}
