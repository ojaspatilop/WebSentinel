// @ts-nocheck
import { StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '../index.css';
import './dashboard.css';
import Landing from './Landing';
import Dashboard from './Dashboard';

function App() {
  const [view, setView] = useState<'landing' | 'dashboard'>('landing');
  return view === 'landing'
    ? <Landing onEnter={() => setView('dashboard')} />
    : <Dashboard />;
}

createRoot(document.getElementById('dashboard-root')!).render(
  <StrictMode><App /></StrictMode>
);
