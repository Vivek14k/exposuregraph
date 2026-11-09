import { useCallback, useEffect, useState } from 'react';
import { KeyRound, Loader2, Lock, ShieldCheck, Waypoints } from 'lucide-react';
import { fetchCurrentUser, loginUser } from '../api';
import type { AuthUser } from '../api';

interface AuthGateProps {
  children: React.ReactNode;
}

type AuthState =
  | { status: 'checking' }
  | { status: 'anonymous'; error?: string }
  | { status: 'authenticated'; user: AuthUser };

const DEMO_PROVISIONING_HINT =
  'No account yet? Create one from the project folder with: python -m backend.cli create-user analyst@example.com. The command securely prompts for a password.';

export const AuthGate: React.FC<AuthGateProps> = ({ children }) => {
  const [state, setState] = useState<AuthState>({ status: 'checking' });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const refreshCurrentUser = useCallback(async () => {
    try {
      const user = await fetchCurrentUser();
      setState(user ? { status: 'authenticated', user } : { status: 'anonymous' });
    } catch (err) {
      setState({
        status: 'anonymous',
        error: err instanceof Error ? err.message : 'Could not verify the current session.',
      });
    }
  }, []);

  useEffect(() => {
    void refreshCurrentUser();
  }, [refreshCurrentUser]);

  // Bounce back to the login view whenever the API layer signals that
  // the session has been invalidated (401 on a non-auth endpoint, logout,
  // CSRF desync, etc.).
  useEffect(() => {
    const handler = () => {
      setState({ status: 'anonymous' });
    };
    window.addEventListener('exposuregraph:unauthorized', handler);
    return () => window.removeEventListener('exposuregraph:unauthorized', handler);
  }, []);

  const handleSubmit = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!email || !password || submitting) return;
      setSubmitting(true);
      try {
        await loginUser(email.trim(), password);
        await refreshCurrentUser();
      } catch (err) {
        setState({
          status: 'anonymous',
          error: err instanceof Error ? err.message : 'Sign in failed.',
        });
      } finally {
        setSubmitting(false);
      }
    },
    [email, password, submitting, refreshCurrentUser],
  );

  if (state.status === 'checking') {
    return (
      <div className="auth-loading" role="status" aria-live="polite">
        <span>
          <Loader2 aria-hidden="true" className="animate-spin" />
          Verifying your ExposureGraph session…
        </span>
      </div>
    );
  }

  if (state.status === 'authenticated') {
    return <>{children}</>;
  }

  const errorMessage = state.status === 'anonymous' ? state.error : undefined;

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-brand">
          <span className="auth-brand-mark">
            <Waypoints aria-hidden="true" />
          </span>
          <span>
            <strong>
              Exposure<span>Graph</span>
            </strong>
            <small>Defensive surface intelligence</small>
          </span>
        </div>

        <div className="auth-card-heading">
          <span className="auth-heading-icon">
            <ShieldCheck aria-hidden="true" />
          </span>
          <div>
            <span className="panel-kicker">PRIVATE WORKSPACE</span>
            <h1>Sign in to continue</h1>
          </div>
        </div>

        <p className="auth-intro">
          Your assessments are tied to a single signed-in workspace. Authenticate to resume voice
          sessions, open saved scans, and launch new authorized assessments.
        </p>

        {errorMessage && (
          <div className="auth-error" role="alert">
            <KeyRound aria-hidden="true" />
            <span>{errorMessage}</span>
          </div>
        )}

        <form className="auth-form" onSubmit={handleSubmit} autoComplete="on">
          <label>
            <span>Email</span>
            <input
              type="email"
              name="email"
              autoComplete="username"
              placeholder="analyst@example.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
              autoFocus
            />
          </label>
          <label>
            <span>Password</span>
            <input
              type="password"
              name="password"
              autoComplete="current-password"
              placeholder="••••••••"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
              minLength={4}
            />
          </label>
          <button type="submit" disabled={submitting}>
            <Lock aria-hidden="true" />
            {submitting ? 'Signing in…' : 'Sign in securely'}
          </button>
        </form>

        <div className="auth-provisioning">
          <ShieldCheck aria-hidden="true" />
          <p>{DEMO_PROVISIONING_HINT}</p>
        </div>
      </div>
    </div>
  );
};

export default AuthGate;
