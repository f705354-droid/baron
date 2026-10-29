/**
 * BARON NEXUS — Shared Enterprise UI Primitives
 * Enforces Zero-Pill static metadata discipline, tabular numerals, WCAG AA contrast,
 * and accessible keyboard-navigable dialogs.
 */

import React from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  FileText,
  Info,
  Lock,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  Criticality,
  EvidenceRecord,
  FindingStatus,
  JobStatus,
  NavigationSectionId,
  Project,
  ScopeRule,
  Severity,
} from '../types/domain.ts';

/**
 * Clean unboxed severity indicator with semantic icon + text (Never hue-only or static pill capsule)
 */
export function SeverityIndicator({ severity }: { severity: Severity | string }) {
  switch (severity) {
    case Severity.CRITICAL:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-400 whitespace-nowrap">
          <AlertOctagon className="w-3.5 h-3.5 shrink-0" />
          <span>Critical</span>
        </span>
      );
    case Severity.HIGH:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400 whitespace-nowrap">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          <span>High</span>
        </span>
      );
    case Severity.MEDIUM:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-sky-400 whitespace-nowrap">
          <Info className="w-3.5 h-3.5 shrink-0" />
          <span>Medium</span>
        </span>
      );
    case Severity.LOW:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-300 whitespace-nowrap">
          <span>Low</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs text-slate-400 whitespace-nowrap">
          <span>{severity}</span>
        </span>
      );
  }
}

export function CriticalityIndicator({ criticality }: { criticality: Criticality | string }) {
  if (criticality === Criticality.MISSION_CRITICAL) {
    return <span className="text-xs font-semibold text-red-400 whitespace-nowrap">Mission Critical</span>;
  }
  if (criticality === Criticality.HIGH) {
    return <span className="text-xs font-medium text-amber-400 whitespace-nowrap">High</span>;
  }
  if (criticality === Criticality.MEDIUM) {
    return <span className="text-xs text-sky-400 whitespace-nowrap">Medium</span>;
  }
  return <span className="text-xs text-slate-400 whitespace-nowrap">{criticality}</span>;
}

export function FindingStatusIndicator({
  status,
  verified,
}: {
  status: FindingStatus | string;
  verified?: boolean;
}) {
  const isConfirmed =
    status === FindingStatus.CONFIRMED ||
    status === FindingStatus.IN_PROGRESS ||
    status === FindingStatus.REMEDIATION_PLANNED;
  const isResolved = status === FindingStatus.RESOLVED;

  return (
    <div className="flex items-center gap-1.5 text-xs whitespace-nowrap">
      {isResolved ? (
        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
      ) : isConfirmed && verified ? (
        <ShieldCheck className="w-3.5 h-3.5 text-sky-400 shrink-0" />
      ) : (
        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
      )}
      <span
        className={
          isResolved
            ? 'text-emerald-400 font-medium'
            : isConfirmed
            ? 'text-slate-100 font-medium'
            : 'text-amber-300'
        }
      >
        {status}
      </span>
      {verified !== undefined && (
        <>
          <span className="text-slate-600" aria-hidden="true">·</span>
          <span className={verified ? 'text-emerald-400/90' : 'text-amber-400/90'}>
            {verified ? 'Verified' : 'Unverified Candidate'}
          </span>
        </>
      )}
    </div>
  );
}

export function JobStatusIndicator({ status }: { status: JobStatus | string }) {
  const colorMap: Record<string, string> = {
    [JobStatus.COMPLETED]: 'text-emerald-400 font-medium',
    [JobStatus.RUNNING]: 'text-sky-400 font-semibold',
    [JobStatus.QUEUED]: 'text-sky-300',
    [JobStatus.AWAITING_APPROVAL]: 'text-amber-400 font-medium',
    [JobStatus.SCOPE_VALIDATION]: 'text-violet-400',
    [JobStatus.FAILED]: 'text-red-400 font-medium',
    [JobStatus.CANCELLED]: 'text-slate-400 line-through',
    [JobStatus.DRAFT]: 'text-slate-400',
  };
  return (
    <span className={`font-mono text-xs whitespace-nowrap ${colorMap[status] || 'text-slate-300'}`}>
      {status}
    </span>
  );
}

export function SectionHeader({
  kicker,
  title,
  subtitle,
  actions,
}: {
  kicker?: string;
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-5 border-b border-slate-800/90">
      <div>
        {kicker && (
          <div className="text-xs font-medium text-sky-400 mb-1 tracking-wide">
            {kicker}
          </div>
        )}
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          {title}
        </h1>
        {subtitle && (
          <p className="mt-1 text-sm text-slate-400 max-w-3xl">
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2.5 shrink-0">{actions}</div>}
    </div>
  );
}

export function ScopeGovernanceBanner({
  project,
  scope,
  killSwitchActive,
  onNavigate,
}: {
  project?: Project;
  scope?: ScopeRule;
  killSwitchActive: boolean;
  onNavigate: (section: NavigationSectionId) => void;
}) {
  if (killSwitchActive) {
    return (
      <div className="bg-red-950/60 border border-red-500/40 rounded-lg px-4 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 text-xs text-red-200">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <span className="font-semibold text-red-300">GLOBAL EMERGENCY STOP ENGAGED</span>
          <span aria-hidden="true">·</span>
          <span>All active and queued assessment operations are halted across all workspaces.</span>
        </div>
        <button
          onClick={() => onNavigate('assessments')}
          className="px-3 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded-md transition-colors whitespace-nowrap shrink-0"
        >
          Manage Emergency Stop
        </button>
      </div>
    );
  }

  if (!project || !scope) return null;

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-lg px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
      <div className="flex flex-wrap items-center gap-2 text-slate-300">
        <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        <span className="font-semibold text-slate-100">{project.code}</span>
        <span className="text-slate-600" aria-hidden="true">·</span>
        <span className="text-emerald-400 font-medium">{project.authorizationStatus}</span>
        <span className="text-slate-600" aria-hidden="true">·</span>
        <span>ROE Ticket: <strong className="font-mono text-slate-200">{scope.authorizationTicketRef}</strong></span>
        <span className="text-slate-600" aria-hidden="true">·</span>
        <span>Policy: <span className="text-sky-300">{project.activePolicyProfile}</span></span>
        <span className="text-slate-600" aria-hidden="true">·</span>
        <span>Authorized Targets: <strong className="font-mono tabular-nums text-slate-200">{scope.authorizedTargets.length}</strong></span>
        <span className="text-slate-600" aria-hidden="true">·</span>
        <span>Exclusions: <strong className="font-mono tabular-nums text-amber-300">{scope.excludedTargets.length}</strong></span>
      </div>
      <div className="flex items-center gap-3">
        {project.isSyntheticDemo && (
          <span className="text-xs text-amber-300/90 font-mono">
            Dataset: Synthetic Demo
          </span>
        )}
        <button
          onClick={() => onNavigate('assets')}
          className="text-xs font-medium text-sky-400 hover:text-sky-300 underline-offset-4 hover:underline whitespace-nowrap shrink-0"
        >
          Inspect Scope Registry
        </button>
      </div>
    </div>
  );
}

export function EvidenceDrawerModal({
  evidence,
  onClose,
}: {
  evidence: EvidenceRecord | null;
  onClose: () => void;
}) {
  if (!evidence) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/70 backdrop-blur-xs">
      <div className="w-full max-w-2xl h-full bg-[#0F1623] border-l border-slate-800 p-6 flex flex-col justify-between overflow-y-auto">
        <div className="space-y-5">
          <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-800">
            <div>
              <div className="text-xs text-sky-400 font-mono mb-1">
                EVIDENCE RECORD · {evidence.id}
              </div>
              <h2 className="text-lg font-bold text-slate-100">{evidence.title}</h2>
            </div>
            <button
              onClick={onClose}
              aria-label="Close evidence viewer"
              className="p-1.5 text-slate-400 hover:text-slate-100 rounded-md hover:bg-slate-800"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-4 text-xs border-b border-slate-800 pb-4">
            <div>
              <span className="text-slate-400 block">Artifact Type</span>
              <span className="text-slate-100 font-medium">{evidence.type}</span>
            </div>
            <div>
              <span className="text-slate-400 block">Linked Record</span>
              <span className="text-slate-100 font-mono">
                {evidence.linkedEntityType} / {evidence.linkedEntityId}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block">Captured By & Timestamp</span>
              <span className="text-slate-100 font-mono">
                {evidence.capturedBy} · {evidence.capturedAt.slice(0, 19).replace('T', ' ')}Z
              </span>
            </div>
            <div>
              <span className="text-slate-400 block">Classification & Origin</span>
              <span className="text-slate-100">
                {evidence.classification} · {evidence.isSynthetic ? 'Synthetic Demo' : 'Captured'}
              </span>
            </div>
            <div className="col-span-2">
              <span className="text-slate-400 block">SHA-256 Integrity Hash</span>
              <span className="text-emerald-400 font-mono break-all">{evidence.sha256Hash}</span>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-300">
                Captured Transcript / Payload Snippet (Redacted)
              </span>
              <span className="text-xs font-mono text-slate-400 tabular-nums">
                {evidence.sizeBytes} bytes · {evidence.mimeType}
              </span>
            </div>
            <pre className="p-4 bg-[#090D14] border border-slate-800 rounded-lg text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {evidence.contentSnippet}
            </pre>
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-400 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-sky-400" />
            Access-controlled evidence artifact
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
          >
            Close Viewer
          </button>
        </div>
      </div>
    </div>
  );
}

export function CommandPaletteModal({
  open,
  onClose,
  onNavigate,
  sections,
}: {
  open: boolean;
  onClose: () => void;
  onNavigate: (id: NavigationSectionId) => void;
  sections: { id: NavigationSectionId; label: string; group: string }[];
}) {
  const [query, setQuery] = React.useState('');
  if (!open) return null;

  const filtered = sections.filter(
    (s) =>
      s.label.toLowerCase().includes(query.toLowerCase()) ||
      s.group.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-black/70 backdrop-blur-xs p-4">
      <div className="w-full max-w-lg bg-[#111827] border border-slate-700 rounded-lg shadow-2xl overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-800">
          <Search className="w-4 h-4 text-sky-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Jump to module, security workflow, or audit log..."
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button
            onClick={onClose}
            className="text-xs font-mono text-slate-400 hover:text-slate-200 px-1.5 py-0.5 border border-slate-700 rounded"
          >
            ESC
          </button>
        </div>
        <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
          {filtered.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                onNavigate(item.id);
                onClose();
              }}
              className="w-full px-4 py-2.5 text-left flex items-center justify-between hover:bg-slate-800/70 transition-colors"
            >
              <span className="text-sm font-medium text-slate-200">{item.label}</span>
              <span className="text-xs text-slate-400">{item.group}</span>
            </button>
          ))}
          {filtered.length === 0 && (
            <div className="px-4 py-6 text-center text-xs text-slate-400">
              No matching modules found for "{query}".
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
