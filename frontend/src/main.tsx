import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';
import { installGlobalDiagnostics } from './lib/diagnostics';
import './index.css';

installGlobalDiagnostics();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
