import type { DashboardPage, NavigationIntent } from '../types';

// Re-export so consumers that import from this module (e.g. App.tsx)
// can resolve `NavigationIntent` without depending on the root types file.
export type { NavigationIntent };

/**
 * Best-effort extraction of a dashboard navigation intent from the
 * assistant's natural-language reply text. Returns null when no
 * recognisable page is mentioned.
 *
 * The parser is intentionally permissive: it scans for any of the
 * supported page keywords, picks up an optional scan id (e.g. "scan
 * #4", "scan 4", "scan-4") and a focus query (e.g. quotes, "titled X",
 * "matching 'X'", "asset X").
 */

const PAGE_KEYWORDS: ReadonlyArray<{ page: DashboardPage; patterns: RegExp[] }> = [
  // Order matters: longer compound phrases must be matched before bare words.
  // Explicit navigational intent required (e.g., "navigating to overview", "showing you findings", "opening graph")
  // Or direct commands like "open findings", "go to assets"
  { page: 'overview', patterns: [/(?:go\s+to|open|switch\s+to|showing(?:\s+you)?|navigating\s+to|routing\s+to|view)\s+(?:the\s+)?(?:overview|dashboard|home)\b/i] },
  { page: 'assets', patterns: [/(?:go\s+to|open|switch\s+to|showing(?:\s+you)?|navigating\s+to|routing\s+to|view)\s+(?:the\s+)?(?:assets?|inventory|hosts?|servers?)\b/i] },
  { page: 'findings', patterns: [/(?:go\s+to|open|switch\s+to|showing(?:\s+you)?|navigating\s+to|routing\s+to|view)\s+(?:the\s+)?(?:findings?|vulnerabilit(?:y|ies)|exposures?|evidence)\b/i] },
  { page: 'graph', patterns: [/(?:go\s+to|open|switch\s+to|showing(?:\s+you)?|navigating\s+to|routing\s+to|view)\s+(?:the\s+)?(?:attack\s+graph|graph|surface\s+map|network\s+map)\b/i] },
  { page: 'history', patterns: [/(?:go\s+to|open|switch\s+to|showing(?:\s+you)?|navigating\s+to|routing\s+to|view)\s+(?:the\s+)?(?:scan\s+history|history|archive|past\s+scans)\b/i] },
  { page: 'reports', patterns: [/(?:go\s+to|open|switch\s+to|showing(?:\s+you)?|navigating\s+to|routing\s+to|view)\s+(?:the\s+)?(?:reports?|dossier|exports?)\b/i] },
  { page: 'assistant', patterns: [/(?:go\s+to|open|switch\s+to|navigating\s+to)\s+(?:the\s+)?assistant\b/i] },
];

const SCAN_ID_PATTERN = /\bscan(?:\s+#?\s*|\s*#|\s*[-–]\s*|\s*#?\s*)(\d{1,9})\b/i;

const FOCUS_QUOTE_PATTERN = /(?:["“][^"”]{1,160}["”]|'[^']{1,160}'|`[^`]{1,160}`)/;
const FOCUS_TITLED_PATTERN = /\btitled\s+(?:["“'`])?([^"”'`.,;:!?\n]{1,120})(?:["”'`])?/i;
const FOCUS_MATCHING_PATTERN = /\b(?:matching|named|called|for|about|called|referenced as)\s+(?:["“'`])?([A-Za-z0-9_.\-*:]{1,120})(?:["”'`])?/i;

function extractScanId(text: string): number | undefined {
  const match = text.match(SCAN_ID_PATTERN);
  if (!match) return undefined;
  const value = Number.parseInt(match[1], 10);
  return Number.isFinite(value) ? value : undefined;
}

function extractFocusQuery(text: string): string | undefined {
  const quote = text.match(FOCUS_QUOTE_PATTERN);
  if (quote) return quote[0].replace(/^["“]|[”"]$/g, '').trim();

  const titled = text.match(FOCUS_TITLED_PATTERN);
  if (titled) return titled[1].trim();

  const matching = text.match(FOCUS_MATCHING_PATTERN);
  if (matching) return matching[1].trim();

  return undefined;
}

export function parseNavigationIntent(text: string): NavigationIntent | null {
  if (!text) return null;

  let resolvedPage: DashboardPage | null = null;
  for (const candidate of PAGE_KEYWORDS) {
    if (candidate.patterns.some((pattern) => pattern.test(text))) {
      resolvedPage = candidate.page;
      break;
    }
  }

  if (!resolvedPage) return null;

  const intent: NavigationIntent = { page: resolvedPage };

  const scanId = extractScanId(text);
  if (scanId !== undefined) intent.scanId = scanId;

  const focusQuery = extractFocusQuery(text);
  if (focusQuery) intent.focusQuery = focusQuery;

  return intent;
}
