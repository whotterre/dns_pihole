import React, { useEffect, useState } from 'react';
import './index.css';

interface Stats {
  total_queries: number;
  blocked_queries: number;
  allowed_queries: number;
  uptime_seconds: number;
}

function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = async () => {
    try {
      const response = await fetch('http://localhost:8000/stats');
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      setStats(data);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 2000); // Polling every 2 seconds
    return () => clearInterval(interval);
  }, []);

  const formatUptime = (seconds: number) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h}h ${m}m ${s}s`;
  };

  return (
    <div className="dashboard-container">
      <header className="header">
        <div className="logo-section">
          <div className="status-indicator active"></div>
          <h1>Pi-hole Dashboard</h1>
        </div>
        <div className="uptime">
          Uptime: {stats ? formatUptime(stats.uptime_seconds) : '---'}
        </div>
      </header>

      <main className="metrics-grid">
        {error && <div className="error-banner">Unable to connect to backend: {error}</div>}
        
        <div className="metric-card">
          <h3>Total Queries</h3>
          <div className="metric-value text-blue">
            {stats ? stats.total_queries.toLocaleString() : '--'}
          </div>
          <div className="metric-trend">+ {stats ? Math.floor(stats.total_queries / Math.max(1, stats.uptime_seconds/60)) : 0}/min</div>
        </div>

        <div className="metric-card">
          <h3>Allowed Queries</h3>
          <div className="metric-value text-green">
            {stats ? stats.allowed_queries.toLocaleString() : '--'}
          </div>
          <div className="metric-trend">Passing through</div>
        </div>

        <div className="metric-card">
          <h3>Blocked Queries</h3>
          <div className="metric-value text-red">
            {stats ? stats.blocked_queries.toLocaleString() : '--'}
          </div>
          <div className="metric-trend">Intercepted</div>
        </div>

        <div className="metric-card block-ratio">
          <h3>Block Ratio</h3>
          <div className="metric-value">
            {stats && stats.total_queries > 0
              ? ((stats.blocked_queries / stats.total_queries) * 100).toFixed(1)
              : '0.0'}
            %
          </div>
          <div className="progress-bar-container">
            <div 
              className="progress-bar" 
              style={{ width: `${stats && stats.total_queries > 0 ? (stats.blocked_queries / stats.total_queries) * 100 : 0}%` }}
            ></div>
          </div>
        </div>
      </main>

      <div className="decoration-circle-1"></div>
      <div className="decoration-circle-2"></div>
    </div>
  );
}

export default App;
