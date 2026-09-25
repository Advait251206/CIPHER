// Shared Tailwind class sets for the SOC dashboard's recurring UI pieces.
// Each mirrors a rule set from the pre-Tailwind stylesheet exactly, including
// cascade outcomes that are easy to miss (noted inline).
import { cn } from '../lib/cn';
import type { ClassValue } from 'clsx';

/* ---------------------------------------------------------------- buttons */

export type ControlBtnVariant = 'default' | 'primary' | 'danger' | 'success';

const controlBtnBase =
  'inline-flex cursor-pointer items-center gap-2 rounded-none border px-[0.85rem] py-[0.45rem] text-[0.8rem] font-semibold ' +
  '[transition:all_0.15s_ease] disabled:cursor-not-allowed disabled:opacity-50 ' +
  // The generic hover sets the border to the surface colour for every variant:
  // variant hover rules never override border-color, so a hovered danger
  // button loses its red border. Kept as it rendered.
  'not-disabled:hover:border-elevated not-disabled:active:transform-[translateY(1px)]';

const controlBtnVariant: Record<ControlBtnVariant, string> = {
  default: 'border-elevated bg-surface text-fg not-disabled:hover:bg-elevated not-disabled:hover:text-fg',
  primary: 'border-accent bg-app text-white not-disabled:hover:bg-app not-disabled:hover:text-white',
  danger: 'border-crit bg-crit-bg text-crit not-disabled:hover:bg-elevated not-disabled:hover:text-crit',
  success: 'border-benign bg-benign-bg text-benign not-disabled:hover:bg-elevated not-disabled:hover:text-benign',
};

export const controlBtn = (variant: ControlBtnVariant = 'default', ...extra: ClassValue[]) =>
  cn(controlBtnBase, controlBtnVariant[variant], ...extra);

export type BtnVariant = 'plain' | 'primary' | 'secondary';

const btnBase =
  'inline-flex cursor-pointer items-center justify-center gap-2 rounded-none border border-transparent bg-transparent px-[1.1rem] py-[0.55rem] ' +
  '[font-family:inherit] text-[0.82rem] font-medium tracking-[0.3px] text-fg outline-none [transition:all_0.2s_ease] ' +
  'disabled:cursor-not-allowed disabled:opacity-50';

const btnVariant: Record<BtnVariant, string> = {
  plain: '',
  primary: 'border-accent bg-accent text-app not-disabled:hover:opacity-85',
  secondary: 'border-line bg-elevated text-fg-2 not-disabled:hover:border-fg not-disabled:hover:text-fg',
};

export const btn = (variant: BtnVariant = 'plain', ...extra: ClassValue[]) => cn(btnBase, btnVariant[variant], ...extra);

export const closeBtn =
  'flex cursor-pointer items-center justify-center rounded-none border-none bg-transparent p-[0.35rem] text-fg-muted ' +
  '[transition:all_0.15s_ease] hover:bg-elevated hover:text-fg';

export const presetPill =
  'inline-flex cursor-pointer items-center gap-[0.4rem] rounded-[9999px] border border-line bg-elevated px-3 py-[0.35rem] ' +
  'text-[0.75rem] font-semibold text-fg [transition:all_0.15s_ease] ' +
  'hover:border-elevated hover:bg-elevated hover:text-accent hover:transform-[translateY(-1px)]';

/* ------------------------------------------------------------------ layout */

export const pageBody = 'mx-auto w-full max-w-[1650px] px-9 pt-7 pb-14 lte-1024:p-5';

export const card =
  'relative rounded-none border border-[rgba(226,232,240,0.85)] bg-app p-[1.35rem] ' +
  '[transition:all_0.22s_cubic-bezier(0.4,0,0.2,1)] hover:border-elevated hover:transform-[translateY(-2px)]';

// Declared after .card in the old stylesheet, so its transition and hover border win.
export const clickableCard =
  'cursor-pointer [transition:border-color_0.2s_ease,transform_0.2s_ease] hover:border-accent hover:transform-[translateY(-2px)]';

export const cardHeader = 'mb-[1.1rem] flex items-center justify-between';
export const cardTitle = 'flex items-center gap-[0.55rem] text-[0.96rem] font-bold text-fg';

/* ------------------------------------------------------------------ tables */

export const tableContainer = 'w-full overflow-x-auto rounded-none border border-line-card bg-surface';

// Descendant variants keep the original specificity (.data-table td = 0,1,1).
export const dataTable =
  'w-full border-collapse text-left text-[0.82rem] ' +
  '[&_th]:border-b [&_th]:border-b-line-card [&_th]:bg-elevated [&_th]:px-4 [&_th]:py-[0.8rem] [&_th]:font-bold [&_th]:tracking-[0.03em] [&_th]:whitespace-nowrap [&_th]:text-fg-2 ' +
  '[&_td]:border-b [&_td]:border-b-line [&_td]:px-4 [&_td]:py-[0.78rem] [&_td]:align-middle [&_td]:text-fg ' +
  '[&_tr:hover_td]:bg-elevated';

// Mirrors the old global `code { ... }` element rule.
export const codeTag =
  'rounded-[4px] border border-line bg-elevated px-[0.4rem] py-[0.15rem] font-mono text-[0.84em] text-fg';

export const mono = 'font-mono text-[0.8rem]';

/* ------------------------------------------------------------------- forms */

export const formGroup = 'mb-4 flex flex-col gap-[0.4rem]';
export const formLabel = 'text-[0.78rem] font-bold text-fg-2';

const formControl =
  'w-full rounded-none border border-elevated bg-input px-[0.85rem] py-[0.6rem] font-sans text-[0.85rem] text-fg outline-none ' +
  '[transition:border-color_0.15s_ease,box-shadow_0.15s_ease] focus:border-accent';

export const formInput = cn(formControl, 'placeholder:text-elevated');
export const formSelect = formControl;
export const formTextarea = cn(formControl, 'min-h-[90px] resize-y font-mono placeholder:text-elevated');

export const input =
  'w-full rounded-none border border-line bg-input px-4 py-3 [font-family:inherit] text-[0.85rem] text-fg outline-none ' +
  '[transition:border-color_0.2s_ease,box-shadow_0.2s_ease] placeholder:text-fg-muted focus:border-accent';

/* ------------------------------------------------------------ status/badges */

export type NavBadgeVariant = 'neutral' | 'danger' | 'active';

const navBadgeVariant: Record<NavBadgeVariant, string> = {
  neutral: 'border-line bg-elevated text-fg-2',
  danger: 'border-crit bg-crit-bg text-crit',
  active: 'border-benign bg-benign-bg text-benign',
};

export const navBadge = (variant: NavBadgeVariant = 'neutral', ...extra: ClassValue[]) =>
  cn('rounded-[9999px] border px-[0.48rem] py-[0.15rem] font-mono text-[0.68rem] font-semibold', navBadgeVariant[variant], ...extra);


export type AlertVariant = 'info' | 'warning' | 'danger' | 'success';

const alertVariant: Record<AlertVariant, string> = {
  info: 'border-elevated bg-elevated text-accent',
  warning: 'border-med bg-elevated text-med',
  danger: 'border-crit bg-elevated text-crit',
  success: 'border-benign bg-elevated text-benign',
};

export const alertBox = (variant?: AlertVariant, ...extra: ClassValue[]) =>
  cn(
    'mb-5 flex items-start gap-[0.85rem] rounded-none border border-transparent px-[1.15rem] py-[0.85rem] text-[0.82rem]',
    variant && alertVariant[variant],
    ...extra
  );

export type ModeBadgeMode = 'detect_only' | 'simulate' | 'enforce';

const modeBadgeMode: Record<ModeBadgeMode, string> = {
  detect_only: 'border border-elevated bg-elevated text-accent',
  simulate: 'border border-med bg-elevated text-med',
  enforce: 'border border-crit bg-elevated text-crit',
};

export const modeBadge = (mode?: string, ...extra: ClassValue[]) =>
  cn(
    'inline-flex items-center gap-[0.4rem] rounded-none px-[0.65rem] py-1 font-mono text-[0.75rem] font-bold uppercase',
    mode && modeBadgeMode[mode as ModeBadgeMode],
    ...extra
  );

/* ------------------------------------------------------------ evidence / kv */

export const evidenceSection = 'mb-4 rounded-none border border-line bg-elevated p-[1.1rem]';
export const evidenceHeader =
  'mb-3 flex items-center gap-2 text-[0.78rem] font-bold tracking-[0.06em] text-accent uppercase';

export const kvGrid = 'grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-x-[1.35rem] gap-y-[0.85rem]';
export const kvItem = 'flex flex-col gap-[0.2rem]';
export const kvLabel = 'text-[0.72rem] font-bold tracking-[0.04em] text-fg-muted uppercase';
export const kvValue = 'text-[0.85rem] font-medium break-all text-fg';

/* ----------------------------------------------------------------- states */

export const stateContainer =
  'flex flex-col items-center justify-center gap-[0.85rem] px-6 py-14 text-center text-fg-muted';
export const stateIcon = 'mb-2 flex size-[48px] items-center justify-center rounded-[50%]';
export const stateTitle = 'text-[1.05rem] font-bold text-fg';
export const stateDesc = 'max-w-[440px] text-[0.85rem] text-fg-2';

export const spinner =
  'size-[32px] animate-spinner rounded-[50%] border-[3px] border-elevated border-t-accent';

export const liveIndicator = 'inline-block size-[8px] animate-pulse-live rounded-[50%] bg-accent';

/* ------------------------------------------------------------------ modals */
// .modal-content/.modal-header/.modal-title/.modal-body were each defined twice
// in the old stylesheet; these are the merged results that actually rendered.

export const modalPanel =
  'flex max-h-[85vh] w-[90%] max-w-[600px] animate-modal-in flex-col overflow-hidden rounded-none border border-line-card bg-surface ' +
  '[box-shadow:0_10px_30px_rgba(0,0,0,0.8)]';
export const modalHeader = 'flex items-center justify-between border-b border-b-line bg-app px-6 py-5';
export const modalTitle = 'flex items-center gap-[0.6rem] text-[1.15rem] font-bold text-fg';
export const modalBody = 'flex-1 overflow-y-auto bg-surface p-6';
export const modalFooter = 'flex items-center justify-end gap-3 border-t border-t-line bg-app px-[1.6rem] py-4';
