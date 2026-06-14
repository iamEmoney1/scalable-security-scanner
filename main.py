from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
import httpx
import sqlite3
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import asyncio

app = FastAPI()

# ==========================================
# STEP 3: AUTOMATED TIMER CONFIGURATION
# ==========================================
scheduler = BackgroundScheduler()

def auto_cron_job():
    print("\n[CRON TIMERS] Executing recurring safety check...")
    try:
        # This tells the background thread to run our scanning logic automatically
        asyncio.run(run_security_scan("google.com"))
    except Exception as e:
        print(f"[CRON ERROR] Auto scan skipped: {str(e)}")

# This sets the background timer to scan google.com every 60 seconds
scheduler.add_job(auto_cron_job, 'interval', seconds=60)
scheduler.start()
# ==========================================

# DATABASE INITIALIZATION
def init_db():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            timestamp TEXT,
            ssl_active INTEGER,
            server TEXT,
            vulnerabilities TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

async def run_security_scan(target_url: str):
    try:
        async with httpx.AsyncClient() as client:
            url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
            response = await client.get(url, timeout=5.0)
            headers = response.headers
            
            has_ssl = 1 if response.url.scheme == "https" else 0
            server_name = headers.get('Server', 'Hidden/Unknown')
            
            missing_headers = []
            if "X-Frame-Options" not in headers: missing_headers.append("Missing X-Frame-Options (Clickjacking Risk)")
            if "Content-Security-Policy" not in headers: missing_headers.append("Missing CSP (XSS Risk)")
            
            vulns_string = ", ".join(missing_headers) if missing_headers else "None Detected"

            conn = sqlite3.connect("scans.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_results (target, timestamp, ssl_active, server, vulnerabilities)
                VALUES (?, ?, ?, ?, ?)
            """, (target_url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), has_ssl, server_name, vulns_string))
            conn.commit()
            conn.close()
            print(f"[DATABASE] Saved automatic check for {target_url}")
    except Exception as e:
        print(f"Scan failed: {str(e)}")

@app.get("/scan")
async def trigger_scan(target: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_security_scan, target)
    return {"status": "Scan Queued", "target": target}

@app.get("/history")
async def get_scan_history():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, timestamp, ssl_active, server, vulnerabilities FROM scan_results ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "target": r[1], "timestamp": r[2], "ssl_enabled": bool(r[3]), "server": r[4], "findings": r[5]} for r in rows]

# FRONTEND DASHBOARD HTML
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scalable Security Engine</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
            .container { max-width: 900px; margin: 0 auto; }
            h1 { color: #38bdf8; }
            .card { background: #1e293b; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 30px; }
            input { width: 70%; padding: 12px; border: none; border-radius: 6px; background: #334155; color: white; font-size: 16px; }
            button { padding: 12px 24px; border: none; border-radius: 6px; background: #0ea5e9; color: white; cursor: pointer; font-size: 16px; font-weight: bold; }
            button:hover { background: #0284c7; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
            th { background: #334155; color: #38bdf8; }
            .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .badge-success { background: #22c55e; color: white; }
            .badge-danger { background: #ef4444; color: white; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Scalable Security Scanner</h1>
            <p>Enter any domain asset to launch a background security analysis.</p>
            
            <div class="card">
                <input type="text" id="targetInput" placeholder="e.g. targetwebsite.com">
                <button onclick="startScan()">Launch Scan</button>
            </div>

            <h2>Scan Log History</h2>
            <div class="card">
                <table>
                    <thead>
                        <tr><th>Target</th><th>Timestamp</th><th>SSL</th><th>Server</th><th>Vulnerabilities</th></tr>
                    </thead>
                    <tbody id="historyTable"></tbody>
                </table>
            </div>
        </div>

        <script>
            async function loadHistory() {
                const res = await fetch('/history');
                const data = await res.json();
                const tbody = document.getElementById('historyTable');
                tbody.innerHTML = '';
                data.forEach(item => {
                    tbody.innerHTML += `
                        <tr>
                            <td><strong>${item.target}</strong></td>
                            <td>${item.timestamp}</td>
                            <td><span class="badge ${item.ssl_enabled ? 'badge-success' : 'badge-danger'}">${item.ssl_enabled ? 'SECURE' : 'NO SSL'}</span></td>
                            <td>${item.server}</td>
                            <td style="color: ${item.findings === 'None Detected' ? '#22c55e' : '#f43f5e'}">${item.findings}</td>
                        </tr>
                    `;
                });
            }

            async function startScan() {
                const target = document.getElementById('targetInput').value;
                if(!target) return alert('Type a domain first!');
                await fetch(`/scan?target=${target}`);
                alert('Scan successfully queued in background!');
                setTimeout(loadHistory, 1500);
            }

            loadHistory();
            setInterval(loadHistory, 10000); // Refresh the UI screen automatically every 10 seconds
        </script>
    </body>
    </html>
    """