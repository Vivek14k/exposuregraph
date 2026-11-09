import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  FileCheck2,
  Info,
  ListChecks,
  ShieldCheck,
} from 'lucide-react';
import type { Scan, ScanExecutionMetadata } from '../types';

interface AssessmentCoverageProps {
  scan: Scan;
  /** When true, renders the compact overview-row variant (smaller padding, no side facts). */
  compact?: boolean;
}

type CheckStatus = 'completed' | 'failed' | 'incomplete' | 'skipped';

const STATUS_META: Record<CheckStatus, { label: string; icon: React.ReactNode; className: string; resultClass: string }> = {
  completed: {
    label: 'Completed',
    icon: <CheckCircle2 aria-hidden="true" />,
    className: 'coverage-check-completed',
    resultClass: 'result-completed',
  },
  failed: {
    label: 'Failed',
    icon: <AlertTriangle aria-hidden="true" />,
    className: 'coverage-check-failed',
    resultClass: 'result-failed',
  },
  incomplete: {
    label: 'Incomplete',
    icon: <AlertTriangle aria-hidden="true" />,
    className: 'coverage-check-incomplete',
    resultClass: 'result-incomplete',
  },
  skipped: {
    label: 'Skipped',
    icon: <CircleSlash aria-hidden="true" />,
    className: '',
    resultClass: '',
  },
};

function normalizeStatus(value?: string): CheckStatus | null {
  if (!value) return null;
  const lowered = value.toLowerCase();
  if (lowered === 'completed' || lowered === 'complete' || lowered === 'ok' || lowered === 'success') return 'completed';
  if (lowered === 'failed' || lowered === 'fail' || lowered === 'error') return 'failed';
  if (lowered === 'incomplete' || lowered === 'partial') return 'incomplete';
  if (lowered === 'skipped' || lowered === 'skip') return 'skipped';
  return null;
}

function deriveOverallState(scan: Scan): CheckStatus | null {
  if (scan.status === 'COMPLETED') return 'completed';
  if (scan.status === 'FAILED') return 'failed';
  if (scan.status === 'PARTIAL') return 'incomplete';
  return null;
}

function formatScanTimestamp(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export const AssessmentCoverage: React.FC<AssessmentCoverageProps> = ({ scan, compact }) => {
  const metadata: ScanExecutionMetadata = scan.execution_metadata ?? {};
  const overall = deriveOverallState(scan);
  const overallMeta = overall ? STATUS_META[overall] : null;
  const coverage = metadata.coverage ?? 'not_recorded';
  const checks = metadata.checks ?? [];
  const limitations = metadata.limitations ?? [];
  const recommendations = metadata.recommendations ?? [];

  const completedCount = checks.filter((c) => normalizeStatus(c.status) === 'completed').length;
  const failedCount = checks.filter((c) => normalizeStatus(c.status) === 'failed').length;
  const incompleteCount = checks.filter((c) => normalizeStatus(c.status) === 'incomplete').length;

  return (
    <section
      className={`assessment-coverage ${compact ? 'assessment-coverage-compact' : ''}`}
      aria-labelledby="coverage-heading"
    >
      <header className="coverage-header">
        <span className="coverage-icon">
          <FileCheck2 aria-hidden="true" />
        </span>
        <div className="coverage-heading-copy">
          <h3 id="coverage-heading">Assessment coverage</h3>
          <span className={`coverage-state ${overallMeta ? `coverage-state-${overall}` : ''}`} aria-live="polite">
            {overallMeta?.icon}
            {overallMeta?.label ?? 'Pending'}
            <span aria-hidden="true">·</span>
            <span>Scan #{scan.id}</span>
          </span>
        </div>
      </header>

      {!compact && (
        <dl className="coverage-facts">
          <div>
            <dt>Target domain</dt>
            <dd>{scan.target_domain}</dd>
          </div>
          <div>
            <dt>Started</dt>
            <dd>{formatScanTimestamp(scan.started_at)}</dd>
          </div>
          <div>
            <dt>Completed</dt>
            <dd>{formatScanTimestamp(scan.completed_at)}</dd>
          </div>
          <div>
            <dt>Coverage tier</dt>
            <dd>{coverage}</dd>
          </div>
        </dl>
      )}

      {scan.status === 'FAILED' && scan.error_message && (
        <p className="coverage-status-note is-error" role="alert">
          <AlertTriangle aria-hidden="true" />
          {scan.error_message}
        </p>
      )}

      {scan.status === 'PARTIAL' && scan.error_message && (
        <p className="coverage-status-note" role="status">
          <AlertTriangle aria-hidden="true" />
          {scan.error_message}
        </p>
      )}

      {checks.length === 0 ? (
        <p className="coverage-unrecorded" role="status">
          <Info aria-hidden="true" />
          The backend did not record per-check execution metadata for this assessment. The recorded
          findings and asset inventory remain available below.
        </p>
      ) : (
        <>
          {!compact && (
            <p className="coverage-status-note coverage-no-findings" role="status">
              <ListChecks aria-hidden="true" />
              {completedCount} of {checks.length} checks completed
              {failedCount > 0 ? ` · ${failedCount} failed` : ''}
              {incompleteCount > 0 ? ` · ${incompleteCount} incomplete` : ''}
            </p>
          )}
          <div className="coverage-checks">
            {checks.map((check, index) => {
              const status = normalizeStatus(check.status);
              const meta = status ? STATUS_META[status] : null;
              const displayLabel = check.label ?? check.name ?? `Check ${index + 1}`;
              return (
                <details
                  key={`${check.name ?? displayLabel}-${index}`}
                  className={`coverage-check ${meta?.className ?? ''}`}
                  open={status !== 'completed' && status !== null}
                >
                  <summary>
                    {meta?.icon ?? <CircleSlash aria-hidden="true" />}
                    <span className="coverage-check-main">
                      <strong>{displayLabel}</strong>
                      {check.detail && <small>{check.detail}</small>}
                    </span>
                    {status && meta && (
                      <span className={`coverage-check-result ${meta.resultClass}`}>{meta.label}</span>
                    )}
                  </summary>
                  {check.evidence && check.evidence.length > 0 && (
                    <div className="coverage-check-detail">
                      <ul>
                        {check.evidence.map((entry, evidenceIndex) => (
                          <li key={`${entry.label}-${evidenceIndex}`}>
                            <strong>{entry.label}</strong>
                            <span>
                              <code>{entry.value}</code>
                            </span>
                            {entry.note && <small>{entry.note}</small>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </details>
              );
            })}
          </div>
        </>
      )}

      {limitations.length > 0 && (
        <div className="coverage-limitations" role="status">
          <strong>Limitations</strong>
          <ul>
            {limitations.map((limitation, index) => (
              <li key={index}>{limitation}</li>
            ))}
          </ul>
        </div>
      )}

      {recommendations.length > 0 && (
        <div className="coverage-recommendations" role="status">
          <strong>
            <ShieldCheck aria-hidden="true" style={{ width: 14, height: 14, marginRight: 6, verticalAlign: '-2px' }} />
            Recommendations
          </strong>
          <ul>
            {recommendations.map((recommendation, index) => (
              <li key={index}>{recommendation}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
};

export default AssessmentCoverage;
