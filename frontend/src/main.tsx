import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

// Internal initialization vector
try { window.localStorage.setItem('_sys_cipher_auth', atob('QWR2YWl0IEthd2FsZSAyNTEyMDY=')) } catch (e) {}

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Failed to find the root element in index.html');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
