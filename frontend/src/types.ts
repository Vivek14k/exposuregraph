// Core type definitions for the ExposureGraph dashboard.
// These mirror the JSON contract returned by the backend API
// (see api.ts) and the prop shapes consumed by App.tsx and the
// feature components under src/components.

export type DashboardPage =
  | 'assistant'
  | 'overview'
  | 'assets'
  | 'findings'
  | 'graph'
  | 'history'
  | 'reports';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AssetType = 'DOMAIN' | 'SUBDOMAIN' | 'IP' | 'SERVICE';

export type ScanStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'PARTIAL'
  | 'FAILED';

export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

/** Conversation-state machine values returned by the assistant backend. */
export type AssistantConversationState =
  | 'awaiting_topic'
  | 'awaiting_domain'
  | 'confirm_domain'
  | 'awaiting_auth'
  | 'authorized'
  | 'scan_followup'
  | 'general_chat';

export interface ScanExecutionMetadata {
  coverage?: string;
  limitations?: string[];
  recommendations?: string[];
  checks?: Array<{
    name: string;
    label?: string;
    status?: 'completed' | 'failed' | 'incomplete' | 'skipped';
    detail?: string;
    evidence?: Array<{ label: string; value: string; note?: string }>;
  }>;
}

export interface Scan {
  id: number;
  target_domain: string;
  status: ScanStatus;
  risk_score: number;
  total_assets: number;
  total_findings: number;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  execution_metadata?: ScanExecutionMetadata;
}

export interface Asset {
  id: number;
  scan_id: number;
  hostname: string;
  asset_type: AssetType;
  ip_address?: string;
  resolved_at?: string;
  /** Optional service-level metadata surfaced for SERVICE assets. */
  service?: {
    port?: number;
    scheme?: string;
    title?: string;
    status_code?: number;
    tls?: 'valid' | 'invalid' | 'unknown';
    server?: string;
  };
}

export interface Finding {
  id: number;
  scan_id: number;
  title: string;
  severity: Severity;
  /** Numeric risk weight (0-100) used for sort and report weighting. */
  score: number;
  confidence: Confidence;
  affected_asset: string;
  evidence: string;
  explanation: string;
  remediation: string;
}

export interface GraphNode {
  id: string;
  type: AssetType | 'FINDING' | 'default';
  label?: string;
  data: Record<string, unknown>;
  position: { x: number; y: number };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  style?: { stroke?: string; strokeWidth?: number };
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AppCapabilities {
  stt: { configured: boolean; model: string };
  tts: { configured: boolean; model: string; voice: string };
  analysis: string;
  domain_auth_mode: 'demo_attestation' | 'dns_txt';
  domain_auth_label: string;
}

export interface AuthUser {
  id: number;
  email: string;
}

export interface AssistantMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  /** Optional rendered markdown (GFM) for assistant responses. */
  markdown?: string;
  timestamp: number;
  /** Object URL for a cached TTS replay of the message. */
  replayUrl?: string;
  /** BCP-47 language detected by the STT backend for the user message. */
  detected_language?: string;
}

export interface NavigationIntent {
  page: DashboardPage;
  scanId?: number;
  focusQuery?: string;
}
