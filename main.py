from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse
import httpx
import sqlite3
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import asyncio

app = FastAPI()

# ==========================================
# CRON AUTOMATED INTERVAL SCANNER
# ==========================================
scheduler = BackgroundScheduler()

def auto_cron_job():
    print("\n[CRON TIMERS] Executing recurring safety check...")
    try:
        asyncio.run(run_security_scan("google.com"))
    except Exception as e:
        print(f"[CRON ERROR] Auto scan skipped: {str(e)}")

scheduler.add_job(auto_cron_job, 'interval', minutes=5) # Sweeps every 5 mins now to prevent spam
scheduler.start()

# ==========================================
# ADVANCED DATABASE SCHEMA
# ==========================================
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
            grade TEXT,
            vulnerabilities TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ==========================================
# DEEP SECURITY SCANNING ENGINE
# ==========================================
async def run_security_scan(target_url: str):
    try:
        async with httpx.AsyncClient() as client:
            # Clean URL format
            clean_url = target_url.strip().replace("http://", "").replace("https://", "")
            base_url = f"https://{clean_url}"
            
            # Start gathering security data
            response = await client.get(base_url, timeout=5.0, follow_redirects=True)
            headers = response.headers
            
            has_ssl = 1 if response.url.scheme == "https" else 0
            server_name = headers.get('Server', 'Hidden / Protected')
            
            # Audit missing protective headers
            missing_headers = []
            score = 100 # Perfect initial score
            
            if "X-Frame-Options" not in headers: 
                missing_headers.append("Missing X-Frame-Options (Clickjacking Risk)")
                score -= 25
            if "Content-Security-Policy" not in headers: 
                missing_headers.append("Missing CSP (Cross-Site Scripting Risk)")
                score -= 30
            if "Strict-Transport-Security" not in headers:
                missing_headers.append("Missing HSTS (Man-in-the-Middle Risk)")
                score -= 15
            if not has_ssl:
                score -= 30

            # Calculate Security Letter Grade
            if score >= 90: grade = "A"
            elif score >= 75: grade = "B"
            elif score >= 50: grade = "C"
            else: grade = "F"
            
            vulns_string = " | ".join(missing_headers) if missing_headers else "None Detected (Excellent Position)"

            # Save full security parameters to relational storage
            conn = sqlite3.connect("scans.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_results (target, timestamp, ssl_active, server, grade, vulnerabilities)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (clean_url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), has_ssl, server_name, grade, vulns_string))
            conn.commit()
            conn.close()
            print(f"[DATABASE] Saved audit report for {clean_url} (Grade: {grade})")
    except Exception as e:
        print(f"[SCAN FAILURE] Couldn't audit {target_url}: {str(e)}")

@app.get("/scan")
async def trigger_scan(target: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_security_scan, target)
    return {"status": "Scan Queued", "target": target}

@app.get("/history")
async def get_scan_history():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, timestamp, ssl_active, server, grade, vulnerabilities FROM scan_results ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "target": r[1], "timestamp": r[2], "ssl_enabled": bool(r[3]), "server": r[4], "grade": r[5], "findings": r[6]} for r in rows]

# ==========================================
# RESPONSIVE FRONTEND SYSTEM
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SaaS Threat Scanner Control Panel</title>
        <style>
            body { font-family: 'Inter', system-ui, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px; margin: 0; }
            .container { max-width: 1000px; margin: 0 auto; }
            header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; border-bottom: 1px solid #1e293b; padding-bottom: 20px; }
            h1 { color: #38bdf8; margin: 0; font-size: 28px; }
            .card { background: #111827; padding: 25px; border-radius: 12px; border: 1px solid #1e293b; margin-bottom: 30px; }
            .flex-input { display: flex; gap: 15px; }
            input { flex: 1; padding: 14px; border: 1px solid #334155; border-radius: 8px; background: #1f2937; color: white; font-size: 16px; }
            button { padding: 14px 28px; border: none; border-radius: 8px; background: #0284c7; color: white; cursor: pointer; font-size: 16px; font-weight: 600; transition: 0.2s; }
            button:hover { background: #0369a1; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 16px; text-align: left; border-bottom: 1px solid #1e293b; }
            th { background: #1f2937; color: #38bdf8; font-weight: 600; }
            .grade-badge { display: inline-block; width: 35px; height: 35px; line-height: 35px; text-align: center; border-radius: 50%; font-weight: bold; font-size: 16px; }
            .grade-A { background: #10b981; color: white; }
            .grade-B { background: #10b981; color: white; opacity: 0.8; }
            .grade-C { background: #f59e0b; color: #0b0f19; }
            .grade-F { background: #ef4444; color: white; }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div>
                    <h1>🛡️ Enterprise Vulnerability Guard</h1>
                    <p style="color: #94a3b8; margin: 5px 0 0 0;">Asynchronous Infrastructure Intelligence Platform</p>
                </div>
            </header>
            
            <div class="card">
                <div class="flex-input">
                    <input type="text" id="targetInput" placeholder="Enter network asset domain (e.g. secure-bank.com)">
                    <button onclick="startScan()">Analyze Risk Posture</button>
                </div>
            </div>

            <h2>Discovered Threat Records</h2>
            <div class="card" style="padding: 0; overflow: hidden;">
                <table>
                    <thead>
                        <tr><th>Target Host</th><th>Timestamp</th><th>Server Blueprint</th><th>Defense Grade</th><th>Identified Vulnerabilities</th></tr>
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
                  <td style="color: ${item.grade === 'A' ? '#10b981' : '#f43f5e'}; font-size: 14px;">${item.findings}</td>
                        </tr>
                    `;
                });
            }

            async function startScan() {
                const target = document.getElementById('targetInput').value;
                if(!target) return alert('Target host configuration domain missing!');
                await fetch(`/scan?target=${target}`);
                alert('Vulnerability scanner pipeline initialized successfully.');
                setTimeout(loadHistory, 1500);
            }
                            <td><code>${item.server}</code></td>
                            <td><span class="grade-badge grade-${item.grade}">${item.grade}</span></td>
          
            loadHistory();
            setInterval(loadHistory, 8000);
        </script>
    </body>
    </html>
    """