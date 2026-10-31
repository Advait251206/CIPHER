/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The backend requires an X-CIPHER-Token header on state-changing requests.
// The dev proxy attaches it server-side so the token never lives in browser code.
const CONFIG_DIR = dirname(fileURLToPath(import.meta.url));
const TOKEN_FILE = resolve(CONFIG_DIR, '../backend/.cipher_token');
const DASHBOARD_ORIGINS = new Set(['http://localhost:5173', 'http://127.0.0.1:5173']);

function readToken(): string {
  if (process.env.CIPHER_API_TOKEN) return process.env.CIPHER_API_TOKEN.trim();
  try {
    return readFileSync(TOKEN_FILE, 'utf-8').trim();
  } catch {
    return ''; // backend not started yet; it creates the file on first run
  }
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq, req) => {
            // Only requests coming from the dashboard itself get the token (CSRF guard).
            const origin = req.headers.origin;
            if (!origin || DASHBOARD_ORIGINS.has(origin)) {
              const token = readToken();
              if (token) proxyReq.setHeader('X-CIPHER-Token', token);
            }
          });
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
  },
});
