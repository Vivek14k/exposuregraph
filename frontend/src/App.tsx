import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bot,
  Boxes,
  CheckCircle2,
  ChevronRight,
  FileCheck2,
  FileText,
  GitBranch,
  Globe2,
  History,
  Layers,
  LayoutDashboard,
  Loader2,
  LogOut,
  Network,
  RefreshCw,
  ScanLine,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Waypoints,
  Zap,
} from 'lucide-react';
import type { Scan, Asset, Finding, GraphData, DashboardPage } from './types';
import { fetchCapabilities, fetchScans, fetchScan, fetchScanAssets, fetchScanFindings, fetchScanGraph, logoutUser } from './api';
import type { AppCapabilities } from './api';
import { NewScanModal } from './components/NewScanModal';
import { ExposureGraphView } from './components/ExposureGraphView';
import { AssetInventory } from './components/AssetInventory';
import { FindingsList } from './components/FindingsList';
import { AssistantHero } from './components/AssistantHero';
import { AssessmentCoverage } from './components/AssessmentCoverage';
import type { NavigationIntent } from './utils/navigationIntent';

const APP_PAGES: Array<{ id: DashboardPage; label: string; icon: React.ReactNode }> = [
  { id: 'assistant', label: 'Assistant', icon: <Bot /> },
  { id: 'overview', label: 'Overview', icon: <LayoutDashboard /> },
  { id: 'assets', label: 'Assets', icon: <Boxes /> },
  { id: 'findings', label: 'Findings', icon: <ShieldAlert /> },
  { id: 'graph', label: 'Attack graph', icon: <Network /> },
  { id: 'history', label: 'Scan history', icon: <History /> },
  { id: 'reports', label: 'Reports', icon: <FileCheck2 /> },
];

export const App: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scansLoaded, setScansLoaded] = useState(false);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState<DashboardPage>('assistant');
  const [detailsScanId, setDetailsScanId] = useState<number | null>(null);
  const [detailsError, setDetailsError] = useState<string | null>(null);
  const [navigationNotice, setNavigationNotice] = useState<string | null>(null);
  const [navigationFocus, setNavigationFocus] = useState<{ page: DashboardPage; query?: string; token: number } | null>(null);
  const navigationSequenceRef = useRef(0);
  const [scansError, setScansError] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState<AppCapabilities | null>(null);

  const loadScans = useCallback(async () => {
    try {
      const data = await fetchScans();
      setScansError(null);
      setScans(data);
      setScansLoaded(true);
      setSelectedScan((selected) => selected ?? data[0] ?? null);
    } catch (err) {
      setScansLoaded(true);
      setScansError(err instanceof Error ? err.message : 'Failed to load scan history.');
      console.error('Failed to load scans:', err);
    }
  }, []);

  useEffect(() => {
    let active = true;
    fetchScans()
      .then((data) => {
        if (!active) return;
        setScansError(null);
        setScans(data);
        setScansLoaded(true);
        setSelectedScan((selected) => selected ?? data[0] ?? null);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setScansLoaded(true);
        setScansError(err instanceof Error ? err.message : 'Failed to load scan history.');
        console.error('Failed to load scans:', err);
      });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    fetchCapabilities()
      .then(setCapabilities)
      .catch(() => setCapabilities(null));
  }, []);

  const loadScanDetails = useCallback(async (scanId: number) => {
    setLoading(true);
    setDetailsError(null);
    setGraphError(null);
    setDetailsScanId(null);
    try {
      const [assetsData, findingsData, graphRes] = await Promise.all([
        fetchScanAssets(scanId),
        fetchScanFindings(scanId),
        fetchScanGraph(scanId).catch((err: unknown) => {
          setGraphError(err instanceof Error ? err.message : 'Failed to load attack graph.');
          return null;
        }),
      ]);
      setAssets(assetsData);
      setFindings(findingsData);
      setGraphData(graphRes);
      setDetailsScanId(scanId);
    } catch (err) {
      setDetailsError(err instanceof Error ? err.message : 'Failed to load scan details.');
    } finally {
      setLoading(false);
    }
  }, []);

  // Poll current scan if RUNNING or PENDING
  useEffect(() => {
    const scanId = selectedScan?.id;
    if (!scanId || (selectedScan.status !== 'RUNNING' && selectedScan.status !== 'PENDING')) return;
      const interval = setInterval(async () => {
        try {
          const updated = await fetchScan(scanId);
          setSelectedScan((current) => (current?.id === scanId ? updated : current));
          if (updated.status !== 'RUNNING' && updated.status !== 'PENDING') {
            await loadScans();
          }
        } catch (err) {
          console.error(err);
        }
      }, 2500);
      return () => clearInterval(interval);
  }, [selectedScan?.id, selectedScan?.status, loadScans]);

  const selectedScanId = selectedScan?.id;
  const selectedScanStatus = selectedScan?.status;
  useEffect(() => {
    if (!selectedScanId || selectedScanStatus === 'RUNNING' || selectedScanStatus === 'PENDING') return;
    const scanId = selectedScanId;
    const timer = window.setTimeout(() => { void loadScanDetails(scanId); }, 0);
    return () => window.clearTimeout(timer);
  }, [selectedScanId, selectedScanStatus, loadScanDetails]);

  const handleScanStarted = (newScan: Scan) => {
    setScans((prev) => [newScan, ...prev.filter((scan) => scan.id !== newScan.id)]);
    setSelectedScan(newScan);
    setCurrentPage('overview');
    setNavigationNotice(`Opening Overview for scan #${newScan.id}.`);
  };

  const handleAssistantNavigation = (intent: NavigationIntent): { success: boolean; message?: string } => {
    const requestedPage = intent.page;
    let targetScan = selectedScan;
    if (intent.scanId !== undefined) {
      targetScan = scans.find((scan) => scan.id === intent.scanId) ??
        (selectedScan?.id === intent.scanId ? selectedScan : null);
      if (!targetScan) {
        if (!scansLoaded) return { success: false, message: 'Scan history is still loading. Try again in a moment.' };
        return { success: false, message: `Scan #${intent.scanId} is not in your accessible scan history, so I could not open it.` };
      }
      setSelectedScan(targetScan);
    }
    const pageLabel = APP_PAGES.find((page) => page.id === requestedPage)?.label ?? 'Overview';
    setNavigationNotice(targetScan
      ? `Opening ${pageLabel} for scan #${targetScan.id}.`
      : `Opening ${pageLabel}.`);
    setNavigationFocus({ page: requestedPage, query: intent.focusQuery, token: ++navigationSequenceRef.current });
    setCurrentPage(requestedPage);
    return { success: true };
  };

  const exportReport = () => {
    if (!selectedScan || detailsScanId !== selectedScan.id || ['PENDING', 'RUNNING'].includes(selectedScan.status)) return;
    const report = {
      report_version: 1,
      generated_at: new Date().toISOString(),
      target_domain: selectedScan.target_domain,
      scan_started_at: selectedScan.started_at ?? null,
      scan_completed_at: selectedScan.completed_at ?? null,
      execution_metadata: selectedScan.execution_metadata ?? null,
      coverage: selectedScan.execution_metadata?.coverage ?? 'not_recorded',
      limitations: selectedScan.execution_metadata?.limitations ?? [],
      recommendations: selectedScan.execution_metadata?.recommendations ?? [],
      severity_breakdown: findings.reduce<Record<string, number>>((totals, finding) => {
        totals[finding.severity] = (totals[finding.severity] ?? 0) + 1;
        return totals;
      }, {}),
      scan: selectedScan,
      assets,
      findings,
      graph: graphData,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `exposuregraph-scan-${selectedScan.id}.json`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const exportFindingsCsv = () => {
    if (!selectedScan || detailsScanId !== selectedScan.id || ['PENDING', 'RUNNING'].includes(selectedScan.status)) return;
    const columns: Array<keyof Finding> = [
      'id', 'title', 'severity', 'score', 'confidence', 'affected_asset',
      'evidence', 'explanation', 'remediation',
    ];
    const escapeCell = (value: string | number) => {
      const text = String(value).replace(/^[\t\r ]*[=+\-@]/, (prefix) => `'${prefix}`);
      return `"${text.replace(/"/g, '""')}"`;
    };
    const rows = [
      ['record_type', 'scan_id', 'target_domain', 'scan_status', 'started_at', 'completed_at', 'recorded_assets', 'recorded_findings', 'coverage', ...columns].map(escapeCell).join(','),
      ['ASSESSMENT_SUMMARY', selectedScan.id, selectedScan.target_domain, selectedScan.status, selectedScan.started_at ?? '', selectedScan.completed_at ?? '', assets.length, findings.length, selectedScan.execution_metadata?.coverage ?? 'not_recorded', ...columns.map(() => '')].map(escapeCell).join(','),
      ...findings.map((finding) => ['FINDING', selectedScan.id, selectedScan.target_domain, selectedScan.status, selectedScan.started_at ?? '', selectedScan.completed_at ?? '', '', '', selectedScan.execution_metadata?.coverage ?? 'not_recorded', ...columns.map((column) => finding[column])].map(escapeCell).join(',')),
    ];
    const blob = new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `exposuregraph-scan-${selectedScan.id}-findings.csv`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const currentPageTitle = APP_PAGES.find((page) => page.id === currentPage)?.label ?? 'Overview';
  const assetTypeCounts = assets.reduce<Record<string, number>>((counts, asset) => {
    counts[asset.asset_type] = (counts[asset.asset_type] ?? 0) + 1;
    return counts;
  }, {});
  const findingSeverityCounts = findings.reduce<Record<string, number>>((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    return counts;
  }, {});
  const criticalFindings = findings.filter((finding) => ['CRITICAL', 'HIGH'].includes(finding.severity));
  const webServices = assets.filter((asset) => asset.asset_type === 'SERVICE').length;
  const discoveredHosts = assets.filter((asset) => ['DOMAIN', 'SUBDOMAIN'].includes(asset.asset_type)).length;
  const resultIsReady = Boolean(
    selectedScan &&
    ['COMPLETED', 'PARTIAL', 'FAILED'].includes(selectedScan.status) &&
    !loading &&
    detailsScanId === selectedScan.id,
  );
  const riskValue = selectedScan && selectedScan.status !== 'FAILED' ? Math.max(0, Math.min(100, selectedScan.risk_score)) : 0;
  const pageHeading: Record<DashboardPage, { eyebrow: string; title: string; description: string }> = {
    assistant: { eyebrow: 'Voice-first security', title: 'Assistant', description: 'Ask about an assessment, or start an authorized scan.' },
    overview: { eyebrow: 'Exposure intelligence', title: 'Surface overview', description: 'A live reading of the assets and findings confirmed in your selected assessment.' },
    assets: { eyebrow: 'Observed infrastructure', title: 'Asset inventory', description: 'Every hostname, public address, and web service recorded by the selected scan.' },
    findings: { eyebrow: 'Evidence-led review', title: 'Security findings', description: 'Prioritized observations with the evidence and remediation attached.' },
    graph: { eyebrow: 'Relationship map', title: 'Attack surface graph', description: 'Trace the recorded links between domains, hosts, services, and findings.' },
    history: { eyebrow: 'Assessment archive', title: 'Scan history', description: 'Reopen an assessment and continue from its stored results.' },
    reports: { eyebrow: 'Export center', title: 'Assessment reports', description: 'Package the evidence from a completed scan for review or handoff.' },
  };
  const pageCopy = pageHeading[currentPage];
  const handleLogout = async () => {
    try {
      await logoutUser();
      window.dispatchEvent(new Event('exposuregraph:unauthorized'));
    } catch (err) {
      setNavigationNotice(err instanceof Error ? err.message : 'Sign out failed.');
    }
  };

  return (
    <div className={`app-shell page-${currentPage}`}>
      <aside className="app-sidebar">
        <div className="sidebar-brand">
          <div className="app-brand-mark"><Waypoints aria-hidden="true" /></div>
          <div className="sidebar-brand-copy">
            <strong>Exposure<span>Graph</span></strong>
            <small>Surface intelligence</small>
          </div>
        </div>

        <div className="workspace-switcher">
          <span className="workspace-avatar">EG</span>
          <span><strong>Demo workspace</strong><small>Local assessment lab</small></span>
          <span className="workspace-status" aria-label="Local workspace" />
        </div>

        <div className="sidebar-nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation" className="app-nav">
          {APP_PAGES.map(({ id, label, icon }) => {
            const count = id === 'assets' && detailsScanId === selectedScan?.id
              ? assets.length
              : id === 'findings' && detailsScanId === selectedScan?.id
                ? findings.length
                : null;
            return (
              <button
                key={id}
                type="button"
                onClick={() => { setNavigationNotice(null); setCurrentPage(id); }}
                aria-current={currentPage === id ? 'page' : undefined}
                className={`app-nav-link ${currentPage === id ? 'is-active' : ''}`}
              >
                <span className="app-nav-icon">{icon}</span>
                <span>{label}</span>
                {count !== null && <span className="nav-count">{count}</span>}
                {id === 'assistant' && <span className="nav-live-mark" title="Voice assistant" />}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-spacer" />
        {selectedScan && (selectedScan.status === 'RUNNING' || selectedScan.status === 'PENDING') && (
          <div className="sidebar-scan-running-card" role="status" aria-label="Scanning active target">
            <span className="running-top"><span className="live-scan-pulse-dot" /> Live Scan Active</span>
            <strong>{selectedScan.target_domain}</strong>
            <div className="progress-track"><div className="progress-bar" /></div>
          </div>
        )}
        <div className="integration-card">
          <div className="integration-card-heading"><span className="integration-spark"><Sparkles /></span><span>VOICE STACK</span></div>
          <div className="integration-row"><span>Prisma · speech to text</span><i className={capabilities?.stt.configured ? 'configured' : ''} /></div>
          <div className="integration-row"><span>Timbre · text to speech</span><i className={capabilities?.tts.configured ? 'configured' : ''} /></div>
          <small>{capabilities ? 'Configuration detected' : 'Checking configuration'}</small>
        </div>
        <div className="sidebar-footnote"><span className="sidebar-footnote-dot" /> Single-user local demo</div>
      </aside>

      <div className="app-workspace">
        <header className="app-header">
          <div className="topbar-context">
            <span className="topbar-root">Exposure surface</span>
            <ChevronRight aria-hidden="true" />
            <strong>{currentPageTitle}</strong>
          </div>
          <div className="app-header-actions">
            {selectedScan && (selectedScan.status === 'RUNNING' || selectedScan.status === 'PENDING') && (
              <div className="live-scan-pulse-badge" role="status" aria-label={`Scan in progress for ${selectedScan.target_domain}`}>
                <span className="live-scan-pulse-dot" />
                <span className="radar-sweep"><Zap size={13} aria-hidden="true" /></span>
                <span>SCAN IN PROGRESS: <strong>{selectedScan.target_domain}</strong></span>
              </div>
            )}
            {selectedScan && (
              <div className="active-scan-chip">
                <span className={`status-dot status-${selectedScan.status.toLowerCase()}`} />
                <span className="active-scan-domain">{selectedScan.target_domain}</span>
                <span className="active-scan-divider" />
                <span className="active-scan-state">{selectedScan.status.toLowerCase()}</span>
              </div>
            )}
            {loading && <span className="sync-indicator"><Loader2 aria-hidden="true" /> Updating</span>}
            <button
              onClick={() => {
                void loadScans();
                if (selectedScan && selectedScan.status !== 'RUNNING' && selectedScan.status !== 'PENDING') {
                  void loadScanDetails(selectedScan.id);
                }
              }}
              className="icon-button"
              title="Refresh assessment data"
              aria-label="Refresh assessment data"
            ><RefreshCw aria-hidden="true" /></button>
            <button onClick={() => void handleLogout()} className="icon-button" title="Sign out" aria-label="Sign out"><LogOut aria-hidden="true" /></button>
          </div>
        </header>

        <main className={`app-main main-${currentPage}`}>
          <div className={currentPage === 'assistant' ? '' : 'hidden'}>
            <AssistantHero
              isOpen={currentPage === 'assistant'}
              onClose={() => setCurrentPage('overview')}
              onExploreDashboard={() => handleAssistantNavigation({ page: 'overview' })}
              onNavigateRequest={handleAssistantNavigation}
              onScanLaunched={handleScanStarted}
              activeScan={selectedScan}
            />
          </div>

          {navigationNotice && currentPage !== 'assistant' && (
            <div role="status" className="app-notice">
              <span><Sparkles aria-hidden="true" />{navigationNotice}</span>
              <button type="button" onClick={() => setNavigationNotice(null)}>Dismiss</button>
            </div>
          )}

          {currentPage === 'overview' && (
            <section className="app-page overview-page" aria-labelledby="overview-heading">
              <PageHeader
                eyebrow={pageCopy.eyebrow}
                title={pageCopy.title}
                description={pageCopy.description}
                action={<button className="quiet-action" onClick={() => setCurrentPage('history')}><History aria-hidden="true" />History<ArrowUpRight aria-hidden="true" /></button>}
              />

              {scansError && <p role="alert" className="callout callout-error">{scansError}</p>}

              <div className={`overview-hero ${selectedScan ? `overview-hero-${selectedScan.status.toLowerCase()}` : 'overview-hero-empty'}`}>
                <div className="overview-hero-copy">
                  <div className="eyebrow-row"><span className={`status-dot ${selectedScan ? `status-${selectedScan.status.toLowerCase()}` : ''}`} />{selectedScan ? `ASSESSMENT #${selectedScan.id}` : 'YOUR SECURITY WORKSPACE'}</div>
                  <h3>{selectedScan?.target_domain ?? 'Map your external surface.'}</h3>
                  <p>{selectedScan
                    ? selectedScan.status === 'RUNNING' || selectedScan.status === 'PENDING'
                      ? 'Discovery is in progress. This view updates as evidence is saved.'
                      : selectedScan.status === 'FAILED'
                        ? selectedScan.error_message || 'The assessment could not complete.'
                        : selectedScan.status === 'PARTIAL'
                          ? selectedScan.error_message || 'Some checks did not complete. Treat this view as partial evidence.'
                          : 'A measured view of the public hosts and web services recorded in this assessment.'
                    : 'Start with a domain you own or are authorized to assess. Confirmed assets and evidence will appear here.'}</p>
                  {selectedScan && <div className="overview-hero-meta"><StatusBadge status={selectedScan.status} /><span>Started {formatTimestamp(selectedScan.started_at)}</span><span className="meta-divider" /><span>Scan #{selectedScan.id}</span></div>}
                  <div className="overview-hero-actions">
                    <button type="button" className="button-primary" onClick={() => handleAssistantNavigation({ page: 'graph' })} disabled={!resultIsReady}><Network aria-hidden="true" />Explore attack graph<ArrowRight aria-hidden="true" /></button>
                    <button type="button" className="button-quiet" onClick={() => setCurrentPage('assistant')}><Bot aria-hidden="true" />Ask the assistant</button>
                  </div>
                </div>
                <div className="overview-hero-visual" aria-label={resultIsReady && selectedScan?.status !== 'FAILED' ? `Risk score ${selectedScan?.risk_score.toFixed(1)} out of 100` : 'No risk score available'}>
                  <div className="risk-orbit" style={{ '--risk': `${riskValue}%` } as React.CSSProperties}>
                    <div className="risk-orbit-inner"><span>{resultIsReady && selectedScan?.status !== 'FAILED' ? selectedScan?.risk_score.toFixed(1) : '—'}</span><small>{resultIsReady && selectedScan?.status !== 'FAILED' ? 'RISK SCORE' : 'NOT SCORED'}</small></div>
                  </div>
                  <div className="orbit-caption"><span className="orbit-caption-mark" />{selectedScan ? `${selectedScan.total_assets} observed records` : 'Awaiting first assessment'}</div>
                </div>
                <div className="overview-hero-grid-lines" aria-hidden="true" />
              </div>

              <div className="metric-grid">
                <MetricCard label="Observed assets" value={resultIsReady ? selectedScan?.total_assets ?? '—' : '—'} detail="Hosts, addresses and services" icon={<Globe2 aria-hidden="true" />} tone="blue" />
                <MetricCard label="Web services" value={resultIsReady ? webServices : '—'} detail="Bounded public endpoint checks" icon={<Server aria-hidden="true" />} tone="violet" />
                <MetricCard label="Priority findings" value={resultIsReady ? criticalFindings.length : '—'} detail="Critical and high severity" icon={<ShieldAlert aria-hidden="true" />} tone="rose" />
                <MetricCard label="Assessment state" value={selectedScan ? titleCase(selectedScan.status) : 'No scan'} detail={selectedScan ? `Updated ${formatTimestamp(selectedScan.completed_at ?? selectedScan.started_at)}` : 'Start an authorized assessment'} icon={selectedScan?.status === 'COMPLETED' ? <CheckCircle2 aria-hidden="true" /> : <Activity aria-hidden="true" />} tone="mint" />
              </div>

              {detailsError && <p role="alert" className="callout callout-error">{detailsError}</p>}
              {selectedScan && selectedScan.status === 'PARTIAL' && <p role="status" className="callout callout-warning">Partial assessment: {selectedScan.error_message || 'Some checks did not produce results.'}</p>}
              {selectedScan && resultIsReady && <AssessmentCoverage scan={selectedScan} compact />}

              <div className="overview-lower-grid">
                <section className="surface-panel composition-panel" aria-labelledby="composition-heading">
                  <div className="panel-heading">
                    <div><span className="panel-kicker">Inventory composition</span><h3 id="composition-heading">Surface mix</h3></div>
                    <span className="panel-total">{resultIsReady ? assets.length : '—'} <small>records</small></span>
                  </div>
                  {resultIsReady && assets.length > 0 ? (
                    <div className="composition-content">
                      <div className="composition-bar" aria-label="Asset type composition">
                        {(['DOMAIN', 'SUBDOMAIN', 'IP', 'SERVICE'] as const).map((type) => (
                          <span key={type} className={`composition-segment composition-${type.toLowerCase()}`} style={{ width: `${(assetTypeCounts[type] ?? 0) / assets.length * 100}%` }} title={`${type}: ${assetTypeCounts[type] ?? 0}`} />
                        ))}
                      </div>
                      <div className="composition-legend">
                        {[
                          ['DOMAIN', 'Root domains'], ['SUBDOMAIN', 'Subdomains'], ['IP', 'Public IPs'], ['SERVICE', 'Web services'],
                        ].map(([type, label]) => (
                          <div className="composition-legend-row" key={type}><span className={`composition-dot composition-${type.toLowerCase()}`} /><span>{label}</span><strong>{assetTypeCounts[type] ?? 0}</strong></div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="panel-empty"><span className="panel-empty-icon"><Globe2 aria-hidden="true" /></span><p>{resultIsReady ? 'No asset records were saved in this assessment.' : selectedScan ? 'Asset records will appear after its results load.' : 'Run an authorized scan to build a measured surface map.'}</p></div>
                  )}
                  <button type="button" className="panel-link" onClick={() => handleAssistantNavigation({ page: 'assets' })} disabled={!resultIsReady}>Open asset inventory<ArrowRight aria-hidden="true" /></button>
                </section>

                <section className="surface-panel priority-panel" aria-labelledby="priority-heading">
                  <div className="panel-heading">
                    <div><span className="panel-kicker">Evidence queue</span><h3 id="priority-heading">Priority signals</h3></div>
                    <button type="button" className="panel-link panel-link-inline" onClick={() => handleAssistantNavigation({ page: 'findings' })} disabled={!resultIsReady}>All findings<ArrowRight aria-hidden="true" /></button>
                  </div>
                  {resultIsReady && findings.length > 0 ? (
                    <div className="priority-list">
                      {[...findings].sort((a, b) => b.score - a.score).slice(0, 3).map((finding) => (
                        <div className="priority-item" key={finding.id}>
                          <span className={`priority-mark severity-${finding.severity.toLowerCase()}`} />
                          <div><strong>{finding.title}</strong><small>{finding.affected_asset}</small></div>
                          <span className={`severity-badge severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="panel-empty"><span className="panel-empty-icon"><ShieldCheck aria-hidden="true" /></span><p>{resultIsReady ? 'No findings were recorded in the available scan evidence.' : 'Findings will appear here when a scan has saved its results.'}</p></div>
                  )}
                </section>
              </div>

              <NewScanModal onScanStarted={handleScanStarted} domainAuthMode={capabilities?.domain_auth_mode ?? 'demo_attestation'} />
            </section>
          )}

          {currentPage === 'history' && (
            <section className="app-page history-page" aria-labelledby="history-heading">
              <PageHeader eyebrow={pageCopy.eyebrow} title={pageCopy.title} description={pageCopy.description} action={<span className="history-total-chip"><History aria-hidden="true" />{scans.length} saved {scans.length === 1 ? 'assessment' : 'assessments'}</span>} />
              {scansError && <p role="alert" className="callout callout-error">{scansError}</p>}
              <div className="history-overview-strip">
                <div><span className="history-strip-icon blue"><ScanLine aria-hidden="true" /></span><span><small>Total assessments</small><strong>{scans.length}</strong></span></div>
                <div><span className="history-strip-icon mint"><CheckCircle2 aria-hidden="true" /></span><span><small>Completed</small><strong>{scans.filter((scan) => scan.status === 'COMPLETED').length}</strong></span></div>
                <div><span className="history-strip-icon violet"><Activity aria-hidden="true" /></span><span><small>In progress</small><strong>{scans.filter((scan) => ['PENDING', 'RUNNING'].includes(scan.status)).length}</strong></span></div>
                <div className="history-strip-note"><span className="history-note-line" /><span>Each row opens the selected scan in Overview.</span></div>
              </div>
              {!scansError && scans.length === 0 ? (
                 <EmptyState title="Your scan archive is empty" message="Authorized assessments will appear here with their real status, risk score and recorded asset counts." actionLabel="Start an authorized assessment" onAction={() => setCurrentPage('overview')} />
              ) : scans.length > 0 ? (
                <div className="history-list" role="list">
                  {scans.map((scan, index) => (
                    <button
                      key={scan.id}
                      type="button"
                      role="listitem"
                      onClick={() => { setSelectedScan(scan); setCurrentPage('overview'); }}
                      className={`history-entry ${selectedScan?.id === scan.id ? 'is-selected' : ''}`}
                    >
                      <span className="history-entry-index">{String(index + 1).padStart(2, '0')}<i /></span>
                      <span className="history-entry-body">
                        <span className="history-entry-topline"><strong>{scan.target_domain}</strong><StatusBadge status={scan.status} /></span>
                        <span className="history-entry-meta"><span>Scan #{scan.id}</span><span>{formatTimestamp(scan.started_at)}</span><span>{scan.total_assets} assets</span><span>{scan.total_findings} findings</span></span>
                        <span className="history-risk-track"><i style={{ width: `${Math.max(0, Math.min(100, scan.risk_score))}%` }} /></span>
                      </span>
                       <span className="history-entry-score"><strong>{scan.status === 'FAILED' ? '—' : scan.risk_score.toFixed(1)}</strong><small>{scan.status === 'FAILED' ? 'not scored' : 'risk / 100'}</small></span>
                      <ArrowUpRight className="history-entry-arrow" aria-hidden="true" />
                    </button>
                  ))}
                </div>
              ) : null}
            </section>
          )}

          {(['assets', 'findings', 'graph', 'reports'] as DashboardPage[]).includes(currentPage) && (
            <section className={`app-page results-page results-page-${currentPage}`} aria-labelledby="results-heading">
              <PageHeader
                eyebrow={pageCopy.eyebrow}
                title={pageCopy.title}
                description={pageCopy.description}
                action={selectedScan ? <div className="result-target"><span className="result-target-mark"><Globe2 aria-hidden="true" /></span><span><small>ACTIVE ASSESSMENT</small><strong>{selectedScan.target_domain}</strong></span><StatusBadge status={selectedScan.status} /></div> : undefined}
              />

              {selectedScan?.status === 'PARTIAL' && <div role="status" className="callout callout-warning"><strong>Partial evidence:</strong> {selectedScan.error_message || 'Some checks did not produce results.'} Displayed records may be incomplete.</div>}

              {!selectedScan ? (
                <EmptyState title="No assessment selected" message="Run an authorized assessment or choose a scan from Scan History to see its evidence." actionLabel="Open Overview" onAction={() => setCurrentPage('overview')} />
              ) : selectedScan.status === 'RUNNING' || selectedScan.status === 'PENDING' ? (
                <div role="status" className="result-state result-state-progress"><span className="result-state-icon"><Activity aria-hidden="true" /></span><div><strong>Assessment in progress</strong><p>Results will appear here when the backend records them.</p></div><Loader2 className="animate-spin" aria-hidden="true" /></div>
              ) : loading || detailsScanId !== selectedScan.id ? (
                <div role="status" className="result-state result-state-progress"><span className="result-state-icon"><Loader2 className="animate-spin" aria-hidden="true" /></span><div><strong>Loading scan evidence</strong><p>Fetching records for scan #{selectedScan.id}.</p></div></div>
              ) : detailsError ? (
                <div role="alert" className="callout callout-error">{detailsError}</div>
              ) : (
                <>
                  {selectedScan.status === 'FAILED' && <div role="alert" className="result-state result-state-error"><span className="result-state-icon"><ShieldAlert aria-hidden="true" /></span><div><strong>Assessment stopped</strong><p>{selectedScan.error_message || 'No complete result is available. Any saved records below remain available for review.'}</p></div></div>}
                  {currentPage === 'assets' && (
                    <div className="result-stat-rail">
                      <div><small>All records</small><strong>{assets.length}</strong></div>
                      <div><small>Hostnames</small><strong>{discoveredHosts}</strong></div>
                      <div><small>Public addresses</small><strong>{assetTypeCounts.IP ?? 0}</strong></div>
                      <div><small>Web services</small><strong>{webServices}</strong></div>
                    </div>
                  )}
                  {currentPage === 'findings' && (
                    <div className="severity-overview">
                      {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((severity) => (
                        <div className={`severity-overview-cell severity-${severity.toLowerCase()}`} key={severity}>
                          <span>{severity}</span><strong>{findingSeverityCounts[severity] ?? 0}</strong>
                          <i><b style={{ width: `${findings.length ? (findingSeverityCounts[severity] ?? 0) / findings.length * 100 : 0}%` }} /></i>
                        </div>
                      ))}
                    </div>
                  )}
                  {currentPage === 'graph' && (
                    <div className="graph-context-strip"><div><span className="graph-context-mark"><Network aria-hidden="true" /></span><span><strong>{graphData?.nodes.length ?? 0} nodes</strong><small>Observed entities</small></span></div><div className="graph-context-connector" /><div><span className="graph-context-mark violet"><GitBranch aria-hidden="true" /></span><span><strong>{graphData?.edges.length ?? 0} links</strong><small>Recorded relationships</small></span></div><span className="graph-context-hint">Select a node to inspect its evidence</span></div>
                  )}

                  {currentPage === 'assets' ? <AssetInventory assets={assets} scan={selectedScan} focusQuery={navigationFocus?.page === 'assets' ? navigationFocus.query : undefined} focusToken={navigationFocus?.page === 'assets' ? navigationFocus.token : 0} /> : null}
                  {currentPage === 'findings' ? <FindingsList findings={findings} scan={selectedScan} focusQuery={navigationFocus?.page === 'findings' ? navigationFocus.query : undefined} focusToken={navigationFocus?.page === 'findings' ? navigationFocus.token : 0} /> : null}
                  {currentPage === 'graph' ? <ExposureGraphView graphData={graphData} isLoading={loading} error={graphError} scan={selectedScan} focusQuery={navigationFocus?.page === 'graph' ? navigationFocus.query : undefined} focusToken={navigationFocus?.page === 'graph' ? navigationFocus.token : 0} /> : null}
                  {currentPage === 'reports' && (
                    <div className="reports-layout">
                      <article className="report-preview">
                        <div className="report-preview-top"><span className="report-brand-mark"><Waypoints aria-hidden="true" /></span><span>EXPOSUREGRAPH <small>ASSESSMENT DOSSIER</small></span><span className="report-preview-version">EG / 0{selectedScan.id}</span></div>
                        <div className="report-preview-body">
                          <span className="report-overline">EXTERNAL ATTACK SURFACE REVIEW</span>
                          <h3>{selectedScan.target_domain}</h3>
                          <p>Assessment #{selectedScan.id} <span /> {formatTimestamp(selectedScan.completed_at ?? selectedScan.started_at)}</p>
                          <div className="report-preview-divider" />
                        <div className="report-preview-score"><div><small>{selectedScan.status === 'FAILED' ? 'RISK SCORE' : 'TRANSPARENT RISK SCORE'}</small><strong>{selectedScan.status === 'FAILED' ? '—' : selectedScan.risk_score.toFixed(1)}{selectedScan.status !== 'FAILED' && <span> / 100</span>}</strong></div><StatusBadge status={selectedScan.status} /></div>
                          <div className="report-severity-bars">
                            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((severity) => (
                              <div className="report-severity-row" key={severity}><span className={`severity-dot severity-${severity.toLowerCase()}`} /><span>{titleCase(severity)}</span><i><b className={`severity-${severity.toLowerCase()}`} style={{ width: `${findings.length ? (findingSeverityCounts[severity] ?? 0) / findings.length * 100 : 0}%` }} /></i><strong>{findingSeverityCounts[severity] ?? 0}</strong></div>
                            ))}
                          </div>
                          <div className="report-preview-footer"><span>{assets.length} assets</span><span>{findings.length} findings</span><span>{graphData?.nodes.length ?? 0} graph nodes</span></div>
                        </div>
                      </article>
                      <section className="report-export-panel">
                        <div className="report-export-heading"><span className="report-export-icon"><FileText aria-hidden="true" /></span><div><span className="panel-kicker">LOCAL EXPORTS</span><h3>Prepare a handoff</h3></div></div>
                        <p>Build a snapshot from the selected scan’s stored evidence. Files are generated in this browser and are not uploaded.</p>
                        <button type="button" className="export-option" onClick={exportReport} disabled={!resultIsReady}><span className="export-option-icon json-icon">{`{ }`}</span><span><strong>Complete scan report</strong><small>JSON · scope, coverage, assets, findings and graph</small></span><span className="export-option-action">Download<ArrowDownRight aria-hidden="true" /></span></button>
                        <button type="button" className="export-option" onClick={exportFindingsCsv} disabled={!resultIsReady}><span className="export-option-icon csv-icon">CSV</span><span><strong>Assessment and findings register</strong><small>CSV · includes a scan summary when there are no findings</small></span><span className="export-option-action">Download<ArrowDownRight aria-hidden="true" /></span></button>
                        <div className="report-includes"><span>INCLUDED IN THIS ASSESSMENT</span><div><CheckCircle2 aria-hidden="true" />Recorded timestamps and status</div><div><CheckCircle2 aria-hidden="true" />Asset inventory and relationships</div><div><CheckCircle2 aria-hidden="true" />Evidence, severity and remediation</div></div>
                        {selectedScan.status === 'PARTIAL' && <p className="report-partial-note">This assessment is partial. The exported file retains its incomplete status.</p>}
                      </section>
                      {resultIsReady && <AssessmentCoverage scan={selectedScan} />}
                    </div>
                  )}
                </>
              )}
            </section>
          )}
        </main>

        <footer className="app-footer">
          <span><strong>ExposureGraph</strong><i />Defensive surface intelligence</span>
          <span>Prisma STT · Timbre TTS when configured · Evidence-based scan answers</span>
        </footer>
      </div>
    </div>
  );
};

export default App;

function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return (
    <div className="page-heading">
      <div className="page-heading-copy"><span className="page-eyebrow"><i />{eyebrow}</span><h2>{title}</h2><p>{description}</p></div>
      {action && <div className="page-heading-action">{action}</div>}
    </div>
  );
}

function MetricCard({ label, value, detail, icon, tone }: { label: string; value: string | number; detail: string; icon: React.ReactNode; tone: 'blue' | 'violet' | 'rose' | 'mint' }) {
  return (
    <div className={`metric-card metric-${tone}`}>
      <span className="metric-card-icon">{icon}</span>
      <div className="metric-card-copy"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
      <span className="metric-card-trace" aria-hidden="true" />
    </div>
  );
}

function EmptyState({ title, message, actionLabel, onAction }: { title: string; message: string; actionLabel?: string; onAction?: () => void }) {
  return (
    <div className="empty-state">
      <span className="empty-state-icon"><Layers aria-hidden="true" /></span>
      <div><h3>{title}</h3><p>{message}</p>{actionLabel && onAction && <button type="button" className="button-quiet" onClick={onAction}>{actionLabel}<ArrowRight aria-hidden="true" /></button>}</div>
    </div>
  );
}

function StatusBadge({ status }: { status: Scan['status'] }) {
  return <span className={`status-badge status-badge-${status.toLowerCase()}`}><i />{titleCase(status)}</span>;
}

function titleCase(value: string) {
  return value.toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatTimestamp(value?: string) {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
