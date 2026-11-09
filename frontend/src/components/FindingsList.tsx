import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowDownUp,
  ChevronRight,
  FileText,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import type { Finding, Scan, Severity } from '../types';

interface FindingsListProps {
  findings: Finding[];
  scan: Scan;
  focusQuery?: string;
  focusToken: number;
}

const SEVERITY_ORDER: ReadonlyArray<Severity> = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CONFIDENCE_DOT: Record<Finding['confidence'], string> = {
  HIGH: '#3fb27f',
  MEDIUM: '#d8a44b',
  LOW: '#a87879',
};

function severityCount(findings: Finding[]): Record<Severity, number> {
  const tally: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const finding of findings) {
    tally[finding.severity] += 1;
  }
  return tally;
}

export const FindingsList: React.FC<FindingsListProps> = ({ findings, scan, focusQuery, focusToken }) => {
  const [activeSeverity, setActiveSeverity] = useState<Severity | 'ALL'>('ALL');
  const [sortDesc, setSortDesc] = useState(true);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const focusCardRef = useRef<HTMLDetailsElement | null>(null);

  useEffect(() => {
    if (focusQuery) {
      setActiveSeverity('ALL');
      setSortDesc(true);
      const match = findings.find((finding) =>
        finding.title.toLowerCase().includes(focusQuery.toLowerCase()) ||
        finding.affected_asset.toLowerCase().includes(focusQuery.toLowerCase()),
      );
      if (match) {
        setExpanded((prev) => {
          const next = new Set(prev);
          next.add(match.id);
          return next;
        });
      }
    }
  }, [focusQuery, focusToken, findings]);

  useEffect(() => {
    if (focusQuery && focusCardRef.current) {
      focusCardRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [focusQuery, focusToken, findings]);

  const counts = useMemo(() => severityCount(findings), [findings]);

  const filtered = useMemo(() => {
    const list = activeSeverity === 'ALL' ? findings : findings.filter((f) => f.severity === activeSeverity);
    return [...list].sort((a, b) => (sortDesc ? b.score - a.score : a.score - b.score));
  }, [findings, activeSeverity, sortDesc]);

  const firstFocusId = useMemo(() => {
    if (!focusQuery) return null;
    const lowered = focusQuery.toLowerCase();
    return filtered.find(
      (finding) =>
        finding.title.toLowerCase().includes(lowered) ||
        finding.affected_asset.toLowerCase().includes(lowered),
    )?.id ?? null;
  }, [filtered, focusQuery]);

  const toggleExpanded = (id: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="findings-list">
      <div className="findings-header">
        <div className="findings-header-copy">
          <span className="findings-header-icon">
            <ShieldAlert aria-hidden="true" />
          </span>
          <div>
            <span className="findings-kicker">EVIDENCE-LED REVIEW</span>
            <h3 className="findings-title">Security findings</h3>
            <p className="findings-description">
              {findings.length} recorded findings for {scan.target_domain} · sorted by score
            </p>
          </div>
        </div>
        <button
          type="button"
          className="findings-sort-label"
          onClick={() => setSortDesc((prev) => !prev)}
          aria-label="Toggle sort order"
        >
          <ArrowDownUp aria-hidden="true" />
          {sortDesc ? 'Highest score first' : 'Lowest score first'}
        </button>
      </div>

      <div className="finding-filter" role="tablist" aria-label="Severity filter">
        <button
          type="button"
          role="tab"
          aria-selected={activeSeverity === 'ALL'}
          className={activeSeverity === 'ALL' ? 'is-active' : ''}
          onClick={() => setActiveSeverity('ALL')}
        >
          All <small>{findings.length}</small>
        </button>
        {SEVERITY_ORDER.map((severity) => (
          <button
            key={severity}
            type="button"
            role="tab"
            aria-selected={activeSeverity === severity}
            className={activeSeverity === severity ? 'is-active' : ''}
            onClick={() => setActiveSeverity(severity)}
          >
            {severity} <small>{counts[severity] ?? 0}</small>
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div className="finding-empty-state" role="status">
          <span className="finding-empty-art">
            <ShieldCheck aria-hidden="true" />
          </span>
          <strong>No findings match the current view</strong>
          <p>
            {findings.length === 0
              ? 'This scan did not record any findings. Run an authorized assessment to surface evidence-backed observations.'
              : 'Adjust the severity filter to see additional findings.'}
          </p>
        </div>
      ) : (
        <div className="finding-card-list">
          {filtered.map((finding) => {
            const isOpen = expanded.has(finding.id);
            const isFocus = firstFocusId === finding.id;
            return (
              <details
                key={finding.id}
                className={`finding-card severity-${finding.severity.toLowerCase()} ${isFocus ? 'is-navigation-focus' : ''}`}
                open={isOpen}
                onToggle={(event) => {
                  const target = event.currentTarget as HTMLDetailsElement;
                  setExpanded((prev) => {
                    const next = new Set(prev);
                    if (target.open) next.add(finding.id);
                    else next.delete(finding.id);
                    return next;
                  });
                }}
                ref={isFocus ? focusCardRef : undefined}
              >
                <summary
                  className="finding-summary"
                  onClick={(event) => {
                    event.preventDefault();
                    toggleExpanded(finding.id);
                  }}
                >
                  <span className="finding-rank">#{finding.id}</span>
                  <span className={`severity-badge severity-${finding.severity.toLowerCase()}`}>
                    {finding.severity}
                  </span>
                  <span className="finding-summary-main">
                    <strong>{finding.title}</strong>
                    <small>{finding.affected_asset}</small>
                  </span>
                  <span className="finding-score">
                    <strong>{finding.score.toFixed(1)}</strong>
                    <small>/ 100</small>
                  </span>
                  <span className="finding-confidence" title={`Confidence: ${finding.confidence}`}>
                    <i style={{ background: CONFIDENCE_DOT[finding.confidence] }} />
                    {finding.confidence}
                  </span>
                  <span className="finding-expand-mark" aria-hidden="true">
                    <ChevronRight />
                  </span>
                </summary>
                <div className="finding-details">
                  <div className="finding-detail evidence">
                    <h5>
                      <AlertTriangle aria-hidden="true" />
                      Evidence
                    </h5>
                    <p>{finding.evidence}</p>
                  </div>
                  <div className="finding-detail impact">
                    <h5>
                      <ShieldAlert aria-hidden="true" />
                      Explanation
                    </h5>
                    <p>{finding.explanation}</p>
                  </div>
                  <div className="finding-detail remediation">
                    <h5>
                      <ShieldCheck aria-hidden="true" />
                      Remediation
                    </h5>
                    <p>{finding.remediation}</p>
                  </div>
                  <div className="finding-detail">
                    <h5>
                      <FileText aria-hidden="true" />
                      Affected asset
                    </h5>
                    <p>{finding.affected_asset}</p>
                  </div>
                </div>
              </details>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default FindingsList;
