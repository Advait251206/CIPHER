/**
 * CIPHER Centralized API Client Layer
 * Handles typed communication with the local-first CIPHER backend.
 * Uses Vite proxy (/api) by default for same-origin security.
 */

import {
  EventsListResponse,
  SecurityEventItem,
  SystemStatsResponse,
  IncidentsListResponse,
  IncidentDetailResponse,
  CorrelationStatsResponse,
  IncidentResolveResponse,
  NetworkHealthResponse,
  NetworkStatsResponse,
  NetworkModelInfoResponse,
  NetworkRulesResponse,
  BlocklistEntry,
  NetworkInterfacesResponse,
  SensorStatusResponse,
  SensorStartRequest,
  NetworkFlowAnalyzeRequest,
  NetworkDetectionResponse,
  PhishingAnalyzeRequest,
  PhishingAnalyzeResponse,
  RulesListResponse,
  RuleDetailResponse,
  RuleToggleResponse,
  RuleEvaluateResponse,
  IOCListResponse,
  IOCDetailResponse,
  IOCCreateRequest,
  IOCToggleResponse,
  IOCCheckRequest,
  IOCCheckResponse,
  IOCImportRequest,
  IOCImportResponse,
  HealthResponse,
  SystemStatusResponse,
  EmailAnalyzeRequest,
  EmailAnalyzeResponse,
  EmailModelInfoResponse,
  EmailHealthResponse,
  PreventionMode,
} from './types';

export class ApiError extends Error {
  public status?: number;
  public detail?: string;
  public isNetworkError: boolean;

  constructor(message: string, status?: number, detail?: string, isNetworkError: boolean = false) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
    this.isNetworkError = isNetworkError;
  }
}

const DEFAULT_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || '/api';

interface RequestOptions extends RequestInit {
  timeoutMs?: number;
  params?: Record<string, string | number | boolean | undefined | null>;
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = 12000, params, ...customConfig } = options;

  let url = `${DEFAULT_BASE_URL}${endpoint}`;
  if (params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== '') {
        searchParams.append(key, String(value));
      }
    }
    const queryString = searchParams.toString();
    if (queryString) {
      url += (url.includes('?') ? '&' : '?') + queryString;
    }
  }

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const reqHeaders: Record<string, string> = {
      Accept: 'application/json',
    };
    if (customConfig.body && typeof customConfig.body === 'string') {
      reqHeaders['Content-Type'] = 'application/json';
    }
    if (customConfig.headers) {
      Object.assign(reqHeaders, customConfig.headers);
    }

    const response = await fetch(url, {
      ...customConfig,
      signal: controller.signal,
      headers: reqHeaders,
    });

    clearTimeout(id);

    if (!response.ok) {
      let errorDetail = '';
      try {
        const errorJson = await response.json();
        errorDetail = errorJson.detail || errorJson.message || JSON.stringify(errorJson);
      } catch {
        errorDetail = await response.text().catch(() => 'Unknown server response');
      }
      throw new ApiError(
        `HTTP ${response.status}: ${response.statusText}`,
        response.status,
        errorDetail,
        false
      );
    }

    // Special handling for 204 or empty responses
    if (response.status === 204) {
      return {} as T;
    }

    return (await response.json()) as T;
  } catch (error: any) {
    clearTimeout(id);
    if (error instanceof ApiError) {
      throw error;
    }
    if (error.name === 'AbortError') {
      throw new ApiError('Request timed out while waiting for CIPHER backend.', 408, 'Timeout', true);
    }
    throw new ApiError(
      'Unable to reach CIPHER API. Ensure backend is running.',
      undefined,
      error.message || 'Network connection failed',
      true
    );
  }
}

// ----------------------------------------------------
// Exported Subsystem API Modules
// ----------------------------------------------------

export const api = {
  // System Health
  health: {
    getHealth: () => request<HealthResponse>('/health'),
    getSystemStatus: () => request<SystemStatusResponse>('/system/status'),
    getVulnerableAppStatus: () => request<import('./types').VulnerableAppStatusResponse>('/vulnerable-app-status'),
  },

  // Vulnerable App Users Management
  vulnerableUsers: {
    list: () => request<import('./types').VulnerableUser[]>('/vulnerable-users/'),
    delete: (id: number) => request<{status: string, message: string}>(`/vulnerable-users/${id}`, { method: 'DELETE' }),
    updatePassword: (id: number, payload: import('./types').UpdatePasswordRequest) => 
      request<{status: string, message: string}>(`/vulnerable-users/${id}/password`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      })
  },

  // Unified Security Events
  events: {
    list: (params?: {
      limit?: number;
      offset?: number;
      event_type?: string;
      attack_type?: string;
      severity?: string;
      source_ip?: string;
      status?: string;
      start_time?: string;
      end_time?: string;
    }) => request<EventsListResponse>('/events', { params }),
    get: (id: string) => request<SecurityEventItem>(`/events/${encodeURIComponent(id)}`),
    getStats: () => request<SystemStatsResponse>('/stats'),
    delete: (id: string) => 
      request<{status: string, deleted: boolean, event_id: string}>(`/events/${encodeURIComponent(id)}`, {
        method: 'DELETE'
      }),
  },

  // Correlated Incidents
  incidents: {
    list: (params?: {
      limit?: number;
      offset?: number;
      status?: string;
      severity?: string;
      source_ip?: string;
    }) => request<IncidentsListResponse>('/incidents', { params }),
    get: (id: string) => request<IncidentDetailResponse>(`/incidents/${encodeURIComponent(id)}`),
    getEvents: (id: string) =>
      request<Record<string, any>[]>(`/incidents/${encodeURIComponent(id)}/events`),
    resolve: (id: string) =>
      request<IncidentResolveResponse>(`/incidents/${encodeURIComponent(id)}/resolve`, {
        method: 'POST',
      }),
    delete: (ids: string[]) =>
      request<{message: string, deleted_count: number}>('/incidents', {
        method: 'DELETE',
        body: JSON.stringify({ incident_ids: ids })
      }),
    getStats: () => request<CorrelationStatsResponse>('/correlation/stats'),
  },

  // Network IDPS & Sensor
  network: {
    getHealth: () => request<NetworkHealthResponse>('/network/health'),
    setPreventionMode: (mode: PreventionMode) =>
      request<{ status: string; mode: PreventionMode }>('/network/prevention-mode', {
        method: 'POST',
        body: JSON.stringify({ mode }),
      }),
    getStats: () => request<NetworkStatsResponse>('/network/stats'),
    getModelInfo: () => request<NetworkModelInfoResponse>('/network/model'),
    listRules: () => request<NetworkRulesResponse>('/network/rules'),
    getBlocklist: (status: string = 'ACTIVE') =>
      request<BlocklistEntry[]>('/network/blocklist', { params: { status } }),
    blockIp: (ip: string) =>
      request<{ status: string; ip: string }>(`/network/blocklist/${encodeURIComponent(ip)}`, {
        method: 'POST',
      }),
    unblockIp: (ip: string) =>
      request<{ status: string; ip: string }>(`/network/blocklist/${encodeURIComponent(ip)}`, {
        method: 'DELETE',
      }),
    getInterfaces: () => request<NetworkInterfacesResponse>('/network/interfaces'),
    getSensorStatus: () => request<SensorStatusResponse>('/network/sensor/status'),
    startSensor: (payload: SensorStartRequest) =>
      request<SensorStatusResponse>('/network/sensor/start', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    stopSensor: () =>
      request<SensorStatusResponse>('/network/sensor/stop', {
        method: 'POST',
      }),
    analyze: (payload: NetworkFlowAnalyzeRequest) =>
      request<NetworkDetectionResponse>('/network/analyze', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  },

  // Phishing URL Analyzer
  phishing: {
    analyze: (payload: PhishingAnalyzeRequest) =>
      request<PhishingAnalyzeResponse>('/phishing/analyze', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  },

  // Heuristic & Signature Rules
  rules: {
    list: (params?: { category?: string; severity?: string; enabled_only?: boolean }) =>
      request<RulesListResponse>('/rules', { params }),
    get: (id: string) => request<RuleDetailResponse>(`/rules/${encodeURIComponent(id)}`),
    enable: (id: string) =>
      request<RuleToggleResponse>(`/rules/${encodeURIComponent(id)}/enable`, { method: 'POST' }),
    disable: (id: string) =>
      request<RuleToggleResponse>(`/rules/${encodeURIComponent(id)}/disable`, { method: 'POST' }),
    evaluate: (payload: Record<string, any>) =>
      request<RuleEvaluateResponse>('/rules/evaluate', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  },

  // Threat Intelligence / Local IOCs
  threatIntel: {
    list: (params?: {
      ioc_type?: string;
      severity?: string;
      enabled_only?: boolean;
      limit?: number;
      offset?: number;
    }) => request<IOCListResponse>('/threat-intel/iocs', { params }),
    get: (id: string) => request<IOCDetailResponse>(`/threat-intel/iocs/${encodeURIComponent(id)}`),
    create: (payload: IOCCreateRequest) =>
      request<IOCDetailResponse>('/threat-intel/iocs', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    delete: (id: string) =>
      request<{ status: string; deleted: boolean; ioc_id: string }>(
        `/threat-intel/iocs/${encodeURIComponent(id)}`,
        { method: 'DELETE' }
      ),
    enable: (id: string) =>
      request<IOCToggleResponse>(`/threat-intel/iocs/${encodeURIComponent(id)}/enable`, {
        method: 'POST',
      }),
    disable: (id: string) =>
      request<IOCToggleResponse>(`/threat-intel/iocs/${encodeURIComponent(id)}/disable`, {
        method: 'POST',
      }),
    check: (payload: IOCCheckRequest) =>
      request<IOCCheckResponse>('/threat-intel/check', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    importJson: (payload: IOCImportRequest) =>
      request<IOCImportResponse>('/threat-intel/import/json', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    importCsv: async (csvContent: string) => {
      // Backend expects raw CSV text in body
      const url = `${DEFAULT_BASE_URL}/threat-intel/import/csv`;
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/csv',
          Accept: 'application/json',
        },
        body: csvContent,
      });
      if (!response.ok) {
        let errDetail = '';
        try {
          const j = await response.json();
          errDetail = j.detail || JSON.stringify(j);
        } catch {
          errDetail = await response.text();
        }
        throw new ApiError(`CSV Import failed: ${response.status}`, response.status, errDetail);
      }
      return (await response.json()) as IOCImportResponse;
    },
  },
  email: {
    analyze: (payload: EmailAnalyzeRequest) =>
      request<EmailAnalyzeResponse>('/email/analyze', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    analyzeText: (text: string) =>
      request<EmailAnalyzeResponse>('/email/analyze-text', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
        },
        body: text,
      }),
    getModelInfo: () => request<EmailModelInfoResponse>('/email/model'),
    getHealth: () => request<EmailHealthResponse>('/email/health'),
  },
  waf: {
    getConfig: () => request<Record<string, 'off' | 'detect' | 'enforce'>>('/waf/config'),
    setMode: (feature: string, mode: 'off' | 'detect' | 'enforce') =>
      request<{ status: string; config: Record<string, 'off' | 'detect' | 'enforce'> }>('/waf/config', {
        method: 'POST',
        body: JSON.stringify({ feature, mode }),
      }).then((r) => r.config),
  },

  extension: {
    getStatus: () => request<import('./types').ExtensionStatusResponse>('/extension/status'),
    launchChrome: (targetUrl?: string) =>
      request<import('./types').ExtensionLaunchResponse>('/extension/launch', {
        method: 'POST',
        body: JSON.stringify({ target_url: targetUrl || 'http://localhost:5173' }),
      }),
    getDownloadUrl: () => '/api/extension/download',
  },
};

