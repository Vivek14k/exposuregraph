import { useCallback, useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  type Node,
  type NodeProps,
  type Edge,
  type NodeMouseHandler,
} from 'reactflow';
import {
  AlertTriangle,
  Globe2,
  Loader2,
  Network,
  Server,
  ShieldAlert,
  X,
} from 'lucide-react';
import type { GraphData, GraphNode, Scan } from '../types';

interface ExposureGraphViewProps {
  graphData: GraphData | null;
  isLoading: boolean;
  error: string | null;
  scan: Scan;
  focusQuery?: string;
  focusToken: number;
}

interface NodeInspection {
  id: string;
  label: string;
  type: string;
  fields: Array<{ label: string; value: string }>;
}

interface FlowNodeData {
  label: string;
  kind: string;
  accent: string;
  icon: React.ReactNode;
  severity?: string;
  detail?: string;
}

const NODE_TYPE_META: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
  DOMAIN: { color: '#1685db', icon: <Globe2 aria-hidden="true" />, label: 'Root domain' },
  SUBDOMAIN: { color: '#7055ef', icon: <Globe2 aria-hidden="true" />, label: 'Subdomain' },
  IP: { color: '#48a981', icon: <Server aria-hidden="true" />, label: 'Public IP' },
  SERVICE: { color: '#d9a14b', icon: <Server aria-hidden="true" />, label: 'Web service' },
  FINDING: { color: '#d66076', icon: <ShieldAlert aria-hidden="true" />, label: 'Finding' },
};

function graphNodeLabel(node: GraphNode): string {
  const label = node.data?.label;
  return typeof label === 'string' && label.trim()
    ? label
    : node.label?.trim() || node.id;
}

function graphNodeType(node: GraphNode): string {
  const assetType = node.data?.asset_type;
  if (typeof assetType === 'string' && NODE_TYPE_META[assetType]) return assetType;
  return node.type === 'default' ? 'IP' : node.type;
}

function layoutGraphNodes(graphNodes: GraphNode[]): Node<FlowNodeData>[] {
  const rank: Record<string, number> = {
    DOMAIN: 0,
    SUBDOMAIN: 1,
    IP: 2,
    SERVICE: 3,
    FINDING: 4,
  };
  const groups = new Map<number, GraphNode[]>();
  for (const graphNode of graphNodes) {
    const nodeRank = rank[graphNodeType(graphNode)] ?? 2;
    const group = groups.get(nodeRank) ?? [];
    group.push(graphNode);
    groups.set(nodeRank, group);
  }

  const positions = new Map<string, { x: number; y: number }>();
  for (const [nodeRank, group] of groups) {
    group.sort((a, b) => graphNodeLabel(a).localeCompare(graphNodeLabel(b), undefined, { numeric: true }));
    const spacing = nodeRank === 0 ? 300 : 270;
    group.forEach((node, index) => {
      positions.set(node.id, {
        x: (index - (group.length - 1) / 2) * spacing,
        y: 70 + nodeRank * 185,
      });
    });
  }

  return graphNodes.map((node) => {
    const type = graphNodeType(node);
    const meta = NODE_TYPE_META[type] ?? NODE_TYPE_META.IP;
    const severity = typeof node.data?.severity === 'string' ? node.data.severity : undefined;
    const detail = type === 'SERVICE'
      ? [node.data?.protocol, node.data?.port].filter(Boolean).join(' · ')
      : typeof node.data?.ip === 'string'
        ? node.data.ip
        : typeof node.data?.ip_address === 'string'
          ? node.data.ip_address
          : undefined;
    return {
      id: node.id,
      type: 'graphEntity',
      position: positions.get(node.id) ?? node.position,
      data: {
        label: graphNodeLabel(node),
        kind: meta.label,
        accent: severity ? severityColor(severity) : meta.color,
        icon: meta.icon,
        severity,
        detail,
      },
    } satisfies Node<FlowNodeData>;
  });
}

function severityColor(severity: string): string {
  return ({
    CRITICAL: '#be123c',
    HIGH: '#dc4c26',
    MEDIUM: '#c27b16',
    LOW: '#6654d9',
    INFO: '#1685db',
  } as Record<string, string>)[severity] ?? '#d66076';
}

const GraphEntityNode: React.FC<NodeProps<FlowNodeData>> = ({ data }) => (
  <div className="graph-entity-node" style={{ '--node-accent': data.accent } as React.CSSProperties} title={data.label}>
    <Handle type="target" position={Position.Top} />
    <span className="graph-entity-icon">{data.icon}</span>
    <span className="graph-entity-copy">
      <span className="graph-entity-kind">
        {data.kind}
        {data.severity && <b>{data.severity}</b>}
      </span>
      <strong>{data.label}</strong>
      {data.detail && <small>{data.detail}</small>}
    </span>
    <Handle type="source" position={Position.Bottom} />
  </div>
);

const NODE_TYPES = { graphEntity: GraphEntityNode };

function toFlowEdges(graphData: GraphData): Edge[] {
  return graphData.edges.map((edge) => {
    const relationship = edge.label?.toLowerCase() ?? '';
    const reverse = relationship.includes('subdomain of');
    const stroke = relationship.includes('has finding')
      ? edge.style?.stroke ?? '#d66076'
      : relationship.includes('runs service')
        ? '#c28b35'
        : relationship.includes('resolves to')
          ? '#7b69c8'
          : '#8a9bb0';
    return {
      id: edge.id,
      source: reverse ? edge.target : edge.source,
      target: reverse ? edge.source : edge.target,
      type: 'smoothstep',
      data: { relationship: edge.label },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
      style: { stroke, strokeWidth: 1.8 },
    };
  });
}

function summarizeNodeFields(node: GraphNode): Array<{ label: string; value: string }> {
  const data = node.data ?? {};
  const fields: Array<{ label: string; value: string }> = [];
  for (const [key, value] of Object.entries(data)) {
    if (key === 'label' || key === 'asset_type') continue;
    if (value === null || value === undefined) continue;
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    if (!text) continue;
    fields.push({ label: key, value: text });
  }
  return fields.slice(0, 6);
}

export const ExposureGraphView: React.FC<ExposureGraphViewProps> = ({
  graphData,
  isLoading,
  error,
  scan,
  focusQuery,
  focusToken,
}) => {
  const [selected, setSelected] = useState<NodeInspection | null>(null);

  const flowNodes = useMemo(() => (graphData ? layoutGraphNodes(graphData.nodes) : []), [graphData]);
  const flowEdges = useMemo(() => (graphData ? toFlowEdges(graphData) : []), [graphData]);
  const nodeTypes = NODE_TYPES;

  const nodeById = useMemo(() => {
    const map = new Map<string, GraphNode>();
    graphData?.nodes.forEach((node) => map.set(node.id, node));
    return map;
  }, [graphData]);

  const handleNodeClick = useCallback<NodeMouseHandler>(
    (_event, flowNode) => {
      const graphNode = nodeById.get(flowNode.id);
      if (!graphNode) return;
      const meta = NODE_TYPE_META[graphNodeType(graphNode)] ?? NODE_TYPE_METADATA_FALLBACK;
      setSelected({
        id: graphNode.id,
        label: graphNodeLabel(graphNode),
        type: meta.label,
        fields: summarizeNodeFields(graphNode),
      });
    },
    [nodeById],
  );

  // Clear inspector + any prior focus state when the scan or focus token changes.
  useEffect(() => {
    setSelected(null);
  }, [scan.id, focusToken]);

  // When the assistant routes us here with a focus query, surface the first
  // matching node in the inspector.
  useEffect(() => {
    if (!focusQuery || !graphData) return;
    const lowered = focusQuery.toLowerCase();
    const match = graphData.nodes.find(
      (node) =>
        graphNodeLabel(node).toLowerCase().includes(lowered) ||
        String(node.data?.hostname ?? '').toLowerCase().includes(lowered) ||
        String(node.data?.ip_address ?? '').toLowerCase().includes(lowered),
    );
    if (match) {
      const meta = NODE_TYPE_META[graphNodeType(match)] ?? NODE_TYPE_METADATA_FALLBACK;
      setSelected({
        id: match.id,
        label: graphNodeLabel(match),
        type: meta.label,
        fields: summarizeNodeFields(match),
      });
    }
  }, [focusQuery, graphData, focusToken]);

  if (isLoading && !graphData) {
    return (
      <div className="graph-state-panel graph-state-loading" role="status">
        <span className="graph-state-art">
          <Loader2 className="animate-spin" aria-hidden="true" />
        </span>
        <div>
          <span className="panel-kicker">ASSEMBLING GRAPH</span>
          <h3>Mapping relationships</h3>
          <p>The backend is reconciling asset and finding relationships for scan #{scan.id}.</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="graph-state-panel graph-state-error" role="alert">
        <span className="graph-state-art">
          <AlertTriangle aria-hidden="true" />
        </span>
        <div>
          <span className="panel-kicker">GRAPH UNAVAILABLE</span>
          <h3>Could not render the attack graph</h3>
          <p>{error}</p>
        </div>
      </div>
    );
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="graph-state-panel" role="status">
        <span className="graph-state-art">
          <Network aria-hidden="true" />
        </span>
        <div>
          <span className="panel-kicker">EMPTY GRAPH</span>
          <h3>No graph relationships recorded</h3>
          <p>This scan did not record any asset relationships. Run a deeper assessment to populate the surface graph.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="graph-shell">
      <div className="graph-toolbar">
        <div className="graph-toolbar-title">
          <span className="graph-toolbar-icon">
            <Network aria-hidden="true" />
          </span>
          <div>
            <strong>Attack surface graph</strong>
            <small>{scan.target_domain} · Scan #{scan.id}</small>
          </div>
        </div>
        <div className="graph-legend" aria-label="Node legend">
          {Object.entries(NODE_TYPE_META).map(([type, meta]) => (
            <span key={type}>
              <i className={`node-color-${type.toLowerCase()}`} style={{ background: meta.color }} />
              {meta.label}
            </span>
          ))}
        </div>
        <div className="graph-toolbar-stats">
          <strong>{graphData.nodes.length}</strong> nodes
          <i />
          <strong>{graphData.edges.length}</strong> links
        </div>
      </div>
      <div className="graph-canvas">
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.18, minZoom: 0.35, maxZoom: 1.1 }}
          minZoom={0.2}
          maxZoom={2.5}
          nodesConnectable={false}
          onNodeClick={handleNodeClick}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={1.4} color="#d8b4e2" />
          <MiniMap
            pannable
            zoomable
            nodeColor={(node) => {
              const graphNode = nodeById.get(node.id);
              const type = graphNode ? graphNodeType(graphNode) : 'IP';
              return NODE_TYPE_META[type]?.color ?? '#8b9cb4';
            }}
            maskColor="rgb(255 255 255 / 65%)"
          />
          <Controls showInteractive={false} />
        </ReactFlow>

        {selected && (
          <aside className="graph-inspector" role="complementary" aria-label={`Inspector for ${selected.label}`}>
            <header className="graph-inspector-header">
              <span className="graph-inspector-icon">
                <Network aria-hidden="true" />
              </span>
              <div>
                <small>{selected.type.toUpperCase()}</small>
                <strong>{selected.label}</strong>
              </div>
              <button type="button" onClick={() => setSelected(null)} aria-label="Close inspector">
                <X aria-hidden="true" />
              </button>
            </header>
            <div className="graph-inspector-body">
              {selected.fields.length === 0 ? (
                <p className="inspector-field">No additional metadata recorded for this node.</p>
              ) : (
                selected.fields.map((field) => (
                  <div className="inspector-field" key={field.label}>
                    <span>{field.label}</span>
                    <code>{field.value}</code>
                  </div>
                ))
              )}
            </div>
          </aside>
        )}
      </div>
      <div className="graph-footnote">
        <span>
          <i /> Graph derived from stored scan evidence. Drag to pan, scroll to zoom.
        </span>
        <span>Scan #{scan.id} · {graphData.nodes.length} entities</span>
      </div>
    </div>
  );
};

const NODE_TYPE_METADATA_FALLBACK = { color: '#8b9cb4', icon: <Server aria-hidden="true" />, label: 'Entity' };

export default ExposureGraphView;
