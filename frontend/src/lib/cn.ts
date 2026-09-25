import { clsx, type ClassValue } from 'clsx';
import { extendTailwindMerge } from 'tailwind-merge';

// Theme colour names from src/index.css. tailwind-merge needs them to tell a
// colour (`text-fg-muted`) from a size (`text-[0.8rem]`) when resolving conflicts.
const colors = [
  'white', 'black',
  'app', 'sidebar', 'card', 'card-hover', 'surface', 'elevated', 'input',
  'line', 'line-card', 'accent',
  'fg', 'fg-2', 'fg-muted', 'fg-inverse',
  'crit', 'crit-bg', 'high', 'high-bg', 'med', 'med-bg', 'low', 'low-bg', 'benign', 'benign-bg',
];

const twMerge = extendTailwindMerge({ extend: { theme: { color: colors } } });

/** Join class names; later utilities override earlier conflicting ones. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
