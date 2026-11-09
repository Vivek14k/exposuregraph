import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Globe2,
  Loader2,
  Mic,
  ScanLine,
  ShieldCheck,
} from 'lucide-react';
import {
  authorizeVerifiedDomain,
  createDomainChallenge,
  requestManualAttestation,
  startScan,
  verifyDomainChallenge,
  type DomainChallenge,
} from '../api';
import type { Scan } from '../types';

interface NewScanModalProps {
  /** Called once the backend confirms the new scan was created. */
  onScanStarted: (scan: Scan) => void;
  /** Either `demo_attestation` (operator confirms ownership) or `dns_txt`. */
  domainAuthMode: 'demo_attestation' | 'dns_txt' | string;
}

type AuthStage =
  | { kind: 'idle' }
  | { kind: 'pending-attestation' }
  | { kind: 'pending-dns-challenge' }
  | { kind: 'dns-challenge'; challenge: DomainChallenge }
  | { kind: 'pending-dns-verify'; challenge: DomainChallenge }
  | { kind: 'launching' };

const DOMAIN_PATTERN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
}

export const NewScanModal: React.FC<NewScanModalProps> = ({ onScanStarted, domainAuthMode }) => {
  const [domainInput, setDomainInput] = useState('');
  const [attested, setAttested] = useState(false);
  const [stage, setStage] = useState<AuthStage>({ kind: 'idle' });
  const [error, setError] = useState<string | null>(null);
  const [lastScan, setLastScan] = useState<Scan | null>(null);

  useEffect(() => {
    // Reset transient state when the auth mode changes (e.g. capabilities
    // loaded after first render).
    setStage({ kind: 'idle' });
    setError(null);
  }, [domainAuthMode]);

  const useDns = domainAuthMode === 'dns_txt';
  const domain = useMemo(() => normalizeDomain(domainInput), [domainInput]);
  const domainValid = DOMAIN_PATTERN.test(domain);
  const canSubmit =
    domainValid &&
    stage.kind === 'idle' &&
    (useDns ? true : attested);

  const resetTransient = useCallback(() => {
    setStage({ kind: 'idle' });
    setError(null);
  }, []);

  const launchScan = useCallback(
    async (domainToLaunch: string, token?: string) => {
      setStage({ kind: 'launching' });
      try {
        const scan = await startScan(domainToLaunch, true, token);
        setLastScan(scan);
        setStage({ kind: 'idle' });
        setDomainInput('');
        setAttested(false);
        onScanStarted(scan);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to start scan.');
        setStage({ kind: 'idle' });
      }
    },
    [onScanStarted],
  );

  const handleSubmit = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!domainValid) {
        setError('Enter a valid domain like example.com.');
        return;
      }
      setError(null);

      try {
        if (useDns) {
          setStage({ kind: 'pending-dns-challenge' });
          const challenge = await createDomainChallenge(domain);
          setStage({ kind: 'dns-challenge', challenge });
        } else {
          setStage({ kind: 'pending-attestation' });
          const attestation = await requestManualAttestation(domain);
          await launchScan(domain, attestation.authorization_token);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Authorization failed.');
        setStage({ kind: 'idle' });
      }
    },
    [domain, domainValid, launchScan, useDns],
  );

  const handleVerifyDns = useCallback(async () => {
    if (stage.kind !== 'dns-challenge') return;
    const challenge = stage.challenge;
    setStage({ kind: 'pending-dns-verify', challenge });
    try {
      const result = await verifyDomainChallenge(challenge.id);
      if (!result.verified) {
        throw new Error('The DNS TXT record could not be verified yet. Allow a moment for propagation and try again.');
      }
      const auth = await authorizeVerifiedDomain(result.domain);
      await launchScan(result.domain, auth.authorization_token);
    } catch (err) {
      setStage({ kind: 'dns-challenge', challenge });
      setError(err instanceof Error ? err.message : 'DNS verification failed.');
    }
  }, [stage, launchScan]);

  const busy =
    stage.kind === 'pending-attestation' ||
    stage.kind === 'pending-dns-challenge' ||
    stage.kind === 'pending-dns-verify' ||
    stage.kind === 'launching';

  return (
    <div className="scan-launcher" aria-labelledby="scan-launcher-heading">
      <div className="scan-launcher-intro">
        <span className="scan-launcher-emblem">
          <ScanLine aria-hidden="true" />
        </span>
        <div className="scan-launcher-copy">
          <span className="panel-kicker">AUTHORIZED ASSESSMENT</span>
          <h3 id="scan-launcher-heading">Start a new exposure scan</h3>
          <p>
            Expose only what you own. Authorize the target domain, then the assistant and backend
            record confirmed assets, services and findings into a fresh assessment.
          </p>
        </div>
        <div className="scan-launcher-voice">
          <span>
            <Mic aria-hidden="true" /> Voice-ready
          </span>
        </div>
      </div>

      <form className="scan-launcher-form" onSubmit={handleSubmit}>
        <label className="scan-target-field">
          <span>Target domain</span>
          <input
            type="text"
            value={domainInput}
            onChange={(event) => {
              setDomainInput(event.target.value);
              if (error) resetTransient();
            }}
            placeholder="example.com"
            autoComplete="off"
            spellCheck={false}
            disabled={busy}
          />
        </label>
        <button
          type="submit"
          className="scan-launcher-submit"
          disabled={!canSubmit || busy}
        >
          {busy ? <Loader2 className="animate-spin" aria-hidden="true" /> : <ScanLine aria-hidden="true" />}
          {useDns ? 'Verify & launch' : 'Launch scan'}
        </button>

        {!useDns && (
          <label className="scan-auth-box" htmlFor="scan-attested">
            <input
              id="scan-attested"
              type="checkbox"
              checked={attested}
              onChange={(event) => setAttested(event.target.checked)}
              disabled={busy}
            />
            <span className="scan-auth-check">
              <CheckCircle2 aria-hidden="true" />
            </span>
            <span>
              <strong>I confirm I own or am authorized to assess this domain.</strong>
              <small>
                Demo attestation mode skips DNS verification for local trials. Production deployments
                switch to DNS TXT challenge automatically.
              </small>
            </span>
          </label>
        )}

        <div className="scan-launcher-assurance">
          <span>
            <i />Scoped to authorized target
          </span>
          <span>
            <i />Evidence saved per scan
          </span>
          <span>
            <i />CSRF-protected launch
          </span>
        </div>
      </form>

      {stage.kind === 'dns-challenge' && (
        <div className="domain-challenge-card" role="status" aria-live="polite">
          <div>
            <Globe2 aria-hidden="true" />
            <strong>DNS TXT verification required</strong>
            <small>Add the following record to your DNS provider, then verify.</small>
          </div>
          <dl>
            <dt>Host</dt>
            <dd>
              <code>{stage.challenge.record_name}</code>
            </dd>
            <dt>Value</dt>
            <dd>
              <code>{stage.challenge.record_value}</code>
            </dd>
            <dt>Expires</dt>
            <dd>
              <code>{new Date(stage.challenge.expires_at).toLocaleString()}</code>
            </dd>
          </dl>
          <p>
            Propagation can take a minute or two. Once the TXT record is visible, click verify to
            authorize and launch the scan.
          </p>
          <button
            type="button"
            className="scan-launcher-submit"
            onClick={() => void handleVerifyDns()}
            disabled={busy}
          >
            <ShieldCheck aria-hidden="true" /> Verify DNS record
          </button>
        </div>
      )}

      {error && (
        <div className="scan-launcher-error" role="alert">
          <AlertTriangle aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      {lastScan && !error && stage.kind === 'idle' && (
        <div className="scan-launcher-error" role="status" style={{ color: '#3f7d52', background: '#f3fbf6', borderColor: '#d6ebe0' }}>
          <CheckCircle2 aria-hidden="true" />
          <span>
            Scan #{lastScan.id} for <strong>{lastScan.target_domain}</strong> is now{' '}
            {lastScan.status.toLowerCase()}.
          </span>
        </div>
      )}
    </div>
  );
};

export default NewScanModal;
