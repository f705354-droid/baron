/**
 * BARON NEXUS — Typed Frontend API Client (/api/v1)
 */

import {
  AIConversationMessage,
  AIToolDefinition,
} from '../server/ai-copilot.ts';
import {
  Asset,
  AssessmentJob,
  AuditEvent,
  CloudContainerCheck,
  DetectionRule,
  EvidenceRecord,
  Finding,
  GraphEdge,
  GraphNode,
  Incident,
  IntegrationConfig,
  LabScenario,
  NotificationItem,
  PluginManifest,
  Project,
  ScopeRule,
  SecurityAlert,
  SecurityReport,
  ThreatIndicator,
  User,
  WebApiCheck,
  Workspace,
} from '../types/domain.ts';

export interface BootstrapPayload {
  user: User;
  availableUsers: User[];
  killSwitchActive: boolean;
  killSwitchTriggeredBy?: string;
  killSwitchTriggeredAt?: string;
  killSwitchReason?: string;
  workspaces: Workspace[];
  projects: Project[];
  activeProject?: Project;
  scopes: ScopeRule[];
  assets: Asset[];
  assessments: AssessmentJob[];
  findings: Finding[];
  evidence: EvidenceRecord[];
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  threatIndicators: ThreatIndicator[];
  detectionRules: DetectionRule[];
  alerts: SecurityAlert[];
  incidents: Incident[];
  cloudChecks: CloudContainerCheck[];
  webApiChecks: WebApiCheck[];
  labScenarios: LabScenario[];
  reports: SecurityReport[];
  integrations: IntegrationConfig[];
  plugins: PluginManifest[];
  auditEvents: AuditEvent[];
  auditIntegrity: {
    valid: boolean;
    totalChecked: number;
    tamperedIndices: number[];
  };
  aiTools: AIToolDefinition[];
  aiConversation: AIConversationMessage[];
  notifications: NotificationItem[];
}

let currentToken: string | null = localStorage.getItem('baron_nexus_token');
let currentUserId: string = localStorage.getItem('baron_nexus_user_id') || 'usr-admin-01';

export function setAuthSession(token: string | null, userId: string) {
  currentToken = token;
  currentUserId = userId;
  if (token) localStorage.setItem('baron_nexus_token', token);
  else localStorage.removeItem('baron_nexus_token');
  localStorage.setItem('baron_nexus_user_id', userId);
}

export function getActiveUserId(): string {
  return currentUserId;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Baron-User-Id': currentUserId,
    ...(options.headers as Record<string, string> | undefined),
  };
  if (currentToken) {
    headers['Authorization'] = `Bearer ${currentToken}`;
  }

  const res = await fetch(`/api/v1${path}`, {
    ...options,
    headers,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const errMsg = data?.message || data?.error || `Request failed with HTTP ${res.status}`;
    throw new Error(errMsg);
  }
  return data as T;
}

export const api = {
  getBootstrap: (projectId?: string) =>
    request<BootstrapPayload>(projectId ? `/bootstrap?projectId=${encodeURIComponent(projectId)}` : '/bootstrap'),

  switchUser: async (userId: string) => {
    const res = await request<{ token: string; user: User }>('/auth/switch-user', {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
    setAuthSession(res.token, res.user.id);
    return res;
  },

  createProject: (payload: Record<string, unknown>) =>
    request<{ project: Project; scope: ScopeRule }>('/projects', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateScope: (scopeId: string, payload: Partial<ScopeRule>) =>
    request<{ scope: ScopeRule }>(`/scopes/${scopeId}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  validateTargetScope: (projectId: string, targets: string[]) =>
    request<{
      validation: {
        passed: boolean;
        checkedAt: string;
        validTargets: string[];
        rejectedTargets: { target: string; reason: string }[];
        policyNotes: string;
      };
    }>('/scopes/validate-target', {
      method: 'POST',
      body: JSON.stringify({ projectId, targets }),
    }),

  createAsset: (payload: Partial<Asset>) =>
    request<{ asset: Asset; deduplicated: boolean }>('/assets', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  deleteAsset: (assetId: string) =>
    request<{ deleted: boolean; assetId: string }>(`/assets/${assetId}`, {
      method: 'DELETE',
    }),

  createAssessment: (payload: {
    projectId: string;
    name: string;
    profile: string;
    requestedTargets: string[];
    requiresApproval?: boolean;
  }) =>
    request<{ job: AssessmentJob }>('/assessments', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  approveAssessment: (jobId: string) =>
    request<{ job: AssessmentJob }>(`/assessments/${jobId}/approve`, {
      method: 'POST',
    }),

  executeAssessment: (jobId: string) =>
    request<{ job: AssessmentJob }>(`/assessments/${jobId}/execute`, {
      method: 'POST',
    }),

  cancelAssessment: (jobId: string) =>
    request<{ job: AssessmentJob }>(`/assessments/${jobId}/cancel`, {
      method: 'POST',
    }),

  toggleKillSwitch: (active: boolean, reason?: string) =>
    request<{
      killSwitchActive: boolean;
      killSwitchTriggeredBy?: string;
      killSwitchTriggeredAt?: string;
      killSwitchReason?: string;
      assessments: AssessmentJob[];
    }>('/assessments/kill-switch', {
      method: 'POST',
      body: JSON.stringify({ active, reason }),
    }),

  createFinding: (payload: Partial<Finding>) =>
    request<{ finding: Finding; deduplicated: boolean }>('/findings', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateFinding: (findingId: string, payload: Partial<Finding>) =>
    request<{ finding: Finding }>(`/findings/${findingId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  addGraphEdge: (payload: Partial<GraphEdge>) =>
    request<{ edge: GraphEdge }>('/attack-paths/edges', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  createThreatIndicator: (payload: Partial<ThreatIndicator>) =>
    request<{ indicator: ThreatIndicator; deduplicated: boolean }>('/threat-intel', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateDetectionRule: (ruleId: string, payload: { enabled?: boolean; queryExpression?: string }) =>
    request<{ rule: DetectionRule }>(`/detection-rules/${ruleId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  updateAlert: (alertId: string, payload: { status?: SecurityAlert['status']; note?: string }) =>
    request<{ alert: SecurityAlert }>(`/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  createIncident: (payload: Partial<Incident>) =>
    request<{ incident: Incident }>('/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateIncidentPlaybook: (
    incidentId: string,
    payload: { stepId?: string; status?: Incident['status']; note?: string }
  ) =>
    request<{ incident: Incident }>(`/incidents/${incidentId}/playbook`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  runLabScenario: (scenarioId: string) =>
    request<{ scenario: LabScenario }>(`/labs/${scenarioId}/run`, {
      method: 'POST',
    }),

  generateReport: (payload: { projectId: string; title: string; reportType: SecurityReport['reportType'] }) =>
    request<{ report: SecurityReport }>('/reports', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  testIntegration: (integrationId: string, endpointUrl?: string) =>
    request<{ integration: IntegrationConfig }>(`/integrations/${integrationId}/test`, {
      method: 'POST',
      body: JSON.stringify({ endpointUrl }),
    }),

  updatePlugin: (pluginId: string, payload: { enabled?: boolean; installed?: boolean }) =>
    request<{ plugin: PluginManifest }>(`/plugins/${pluginId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  updateUserRole: (userId: string, payload: { role?: string; status?: string }) =>
    request<{ user: User }>(`/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  sendAIChat: (payload: {
    projectId: string;
    prompt: string;
    toolId?: string;
    toolArgs?: Record<string, string>;
  }) =>
    request<{
      reply: AIConversationMessage;
      liveGeminiUsed: boolean;
      conversation: AIConversationMessage[];
    }>('/ai/chat', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  clearAIChat: (projectId: string) =>
    request<{ cleared: boolean }>(`/ai/chat/${projectId}`, {
      method: 'DELETE',
    }),

  purgeSyntheticData: () =>
    request<{ purgedCounts: Record<string, number> }>('/system/purge-synthetic', {
      method: 'POST',
    }),

  resetDemoData: () =>
    request<{ reset: boolean }>('/system/reset-demo', {
      method: 'POST',
    }),
};
