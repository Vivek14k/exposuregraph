import { useEffect, useMemo, useRef, useState } from 'react';
import { Boxes, Globe2, Search, Server } from 'lucide-react';
import type { Asset, AssetType, Scan } from '../types';

interface AssetInventoryProps {
  assets: Asset[];
  scan: Scan;
  focusQuery?: string;
  focusToken: number;
}

const ASSET_TYPES: ReadonlyArray<AssetType> = ['DOMAIN', 'SUBDOMAIN', 'IP', 'SERVICE'];

const ASSET_TYPE_ICON: Record<AssetType, React.ReactNode> = {
  DOMAIN: <Globe2 aria-hidden="true" />,
  SUBDOMAIN: <Globe2 aria-hidden="true" />,
  IP: <Server aria-hidden="true" />,
  SERVICE: <Server aria-hidden="true" />,
};

function formatResolvedAt(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export const AssetInventory: React.FC<AssetInventoryProps> = ({ assets, scan, focusQuery, focusToken }) => {
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<AssetType | 'ALL'>('ALL');
  const focusRowRef = useRef<HTMLTableRowElement | null>(null);

  // Pre-seed the search box when the assistant navigates here with a query.
  useEffect(() => {
    if (focusQuery) {
      setQuery(focusQuery);
      setTypeFilter('ALL');
    }
  }, [focusQuery, focusToken]);

  // Scroll the first matching row into view when a focus query is set.
  useEffect(() => {
    if (focusQuery && focusRowRef.current) {
      focusRowRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [focusQuery, focusToken, assets]);

  const counts = useMemo(() => {
    const tally: Record<string, number> = { DOMAIN: 0, SUBDOMAIN: 0, IP: 0, SERVICE: 0 };
    for (const asset of assets) {
      tally[asset.asset_type] = (tally[asset.asset_type] ?? 0) + 1;
    }
    return tally;
  }, [assets]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return assets.filter((asset) => {
      if (typeFilter !== 'ALL' && asset.asset_type !== typeFilter) return false;
      if (!needle) return true;
      return (
        asset.hostname.toLowerCase().includes(needle) ||
        (asset.ip_address ?? '').toLowerCase().includes(needle)
      );
    });
  }, [assets, query, typeFilter]);

  const firstFocusId = useMemo(() => {
    if (!focusQuery) return null;
    const lowered = focusQuery.toLowerCase();
    return filtered.find(
      (asset) =>
        asset.hostname.toLowerCase().includes(lowered) ||
        (asset.ip_address ?? '').toLowerCase().includes(lowered),
    )?.id ?? null;
  }, [filtered, focusQuery]);

  return (
    <div className="asset-inventory">
      <div className="asset-inventory-header">
        <div className="asset-inventory-title-block">
          <span className="asset-type-icon" aria-hidden="true">
            <Boxes />
          </span>
          <div className="asset-inventory-title-line">
            <h3 className="asset-inventory-title">Asset inventory</h3>
            <p className="asset-inventory-description">
              Hostnames, addresses and web services recorded for scan #{scan.id}.
            </p>
          </div>
        </div>
        <div className="asset-filters">
          <label className="asset-search">
            <Search aria-hidden="true" />
            <input
              type="search"
              placeholder="Filter by hostname or IP…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              aria-label="Filter assets"
            />
          </label>
          <label className="asset-filter-select">
            <select
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value as AssetType | 'ALL')}
              aria-label="Filter by asset type"
            >
              <option value="ALL">All types</option>
              {ASSET_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type.charAt(0) + type.slice(1).toLowerCase()}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      <div className="asset-type-ribbon" role="list">
        {ASSET_TYPES.map((type) => (
          <div key={type} role="listitem">
            <span className={`asset-type-icon ${type.toLowerCase()}`}>{ASSET_TYPE_ICON[type]}</span>
            <span>
              <small>{type}</small>
              <strong>{counts[type] ?? 0}</strong>
            </span>
          </div>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div className="asset-empty-state" role="status">
          <span className="asset-empty-art">
            <Boxes aria-hidden="true" />
          </span>
          <strong>No matching asset records</strong>
          <p>
            {assets.length === 0
              ? 'This scan did not record any assets. Run a deeper assessment to populate the inventory.'
              : 'No assets match the current filters. Try clearing the search or choosing "All types".'}
          </p>
        </div>
      ) : (
        <div className="asset-table-scroll">
          <table className="asset-table">
            <caption className="sr-only" style={{ position: 'absolute', left: '-9999px' }}>
              Asset inventory for scan #{scan.id} — {filtered.length} of {assets.length} records
            </caption>
            <thead>
              <tr>
                <th scope="col">#</th>
                <th scope="col">Hostname</th>
                <th scope="col">Type</th>
                <th scope="col">IP address</th>
                <th scope="col">Resolved</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((asset, index) => {
                const isFocus = firstFocusId === asset.id;
                return (
                  <tr
                    key={asset.id}
                    className={isFocus ? 'is-navigation-focus' : undefined}
                    ref={isFocus ? focusRowRef : undefined}
                  >
                    <td className="asset-row-number">{String(index + 1).padStart(2, '0')}</td>
                    <td>
                      <span className="asset-identifier">{asset.hostname}</span>
                      {asset.service?.title && (
                        <span className="asset-subidentifier">{asset.service.title}</span>
                      )}
                    </td>
                    <td>
                      <span className={`asset-type-badge asset-type-${asset.asset_type.toLowerCase()}`}>
                        <i />
                        {asset.asset_type}
                      </span>
                    </td>
                    <td>
                      {asset.ip_address ? (
                        <span className="asset-ip-value">{asset.ip_address}</span>
                      ) : (
                        <span className="asset-muted-value">—</span>
                      )}
                    </td>
                    <td>{formatResolvedAt(asset.resolved_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="asset-table-foot">
        <span>
          <i /> Showing {filtered.length} of {assets.length} records · scan #{scan.id}
        </span>
        <span>Source: stored assessment evidence</span>
      </div>
    </div>
  );
};

export default AssetInventory;
