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
# THE AUTH-BACKED FRONTEND UI GATEWAY
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def serve_portal():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Threat Scanner Gateway</title>
        <style>
            body { font-family: 'Inter', sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px; display: flex; justify-content: center; align-items: center; height: 80vh; }
            .auth-card { background: #111827; padding: 35px; border-radius: 12px; border: 1px solid #1e293b; width: 350px; text-align: center; }
            h2 { color: #38bdf8; margin-top: 0; }
            input { width: 90%; padding: 12px; margin: 10px 0; border: 1px solid #334155; border-radius: 6px; background: #1f2937; color: white; }
            button { width: 98%; padding: 12px; border: none; border-radius: 6px; background: #0284c7; color: white; font-weight: bold; cursor: pointer; margin-top: 10px; }
            button:hover { background: #0369a1; }
            .toggle-link { color: #94a3b8; font-size: 14px; margin-top: 15px; cursor: pointer; display: inline-block; }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 16px; border-bottom: 1px solid #1e293b; }
        </style>
    </head>
    <body>
        <div class="auth-card" id="loginCard">
            <h2>🛡️ Scanner Login</h2>
            <p style="color: #94a3b8; font-size: 14px;">Access your private security terminal</p>
            <input type="text" id="loginUser" placeholder="Username">
            <input type="password" id="loginPass" placeholder="Password">
            <button onclick="login()">Enter Dashboard</button>
            <div class="toggle-link" onclick="toggleAuth()">Create an enterprise account →</div>
        </div>

        <div class="auth-card" id="registerCard" style="display: none;">
            <h2>📝 Register Account</h2>
            <form action="/register" method="post">
                <input type="text" name="username" placeholder="Choose Username" required>
                <input type="password" name="password" placeholder="Choose Password" required>
                <button type="submit">Create Account</button>
            </form>
            <div class="toggle-link" onclick="toggleAuth()">← Back to login</div>
        </div>

        <div id="dashboardContainer" style="display: none; width: 900px; position: absolute; top: 40px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                <div>
                    <h1 style="color: #38bdf8; margin:0;">🛡️ Enterprise Threat Console</h1>
                    <p style="color: #94a3b8; margin: 5px 0 0 0;">Logged in as: <span id="userBadge" style="color: white; font-weight: bold;"></span></p>
                </div>
                <button onclick="logout()" style="width: auto; background: #334155; padding: 10px 20px; color: white; border: none; border-radius: 6px; cursor: pointer;">Logout</button>
            </div>
            
            <div style="background: #111827; padding: 25px; border-radius: 12px; border: 1px solid #1e293b; margin-bottom:30px; display: flex; gap: 15px;">
                <input type="text" id="targetInput" placeholder="Enter network asset domain (e.g. secure-bank.com)" style="flex: 1;">
                <button onclick="startScan()" style="width: auto; padding: 0 25px; background: #0284c7; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;">Analyze Risk Posture</button>
            </div>

            <div style="background: #111827; border-radius: 12px; border: 1px solid #1e293b; overflow: hidden;">
                <table>
                    <thead>
                        <tr style="background: #1f2937; color: #38bdf8;"><th>Target</th><th>Timestamp</th><th>Server</th><th>Grade</th><th>Vulnerabilities</th></tr>
                    </thead>
                    <tbody id="historyTable"></tbody>
                </table>
            </div>
        </div>

        <script>
            let currentUser = "";

            function toggleAuth() {
                const loginCard = document.getElementById('loginCard');
                const registerCard = document.getElementById('registerCard');
                if(loginCard.style.display === 'none') {
                    loginCard.style.display = 'block';
                    registerCard.style.display = 'none';
                } else {
                    loginCard.style.display = 'none';
                    registerCard.style.display = 'block';
                }
            }

            async function login() {
                const user = document.getElementById('loginUser').value;
                const pass = document.getElementById('loginPass').value;
                if(!user || !pass) return alert('Fill in all credentials!');
                
                currentUser = user;
                document.getElementById('loginCard').style.display = 'none';
                document.getElementById('dashboardContainer').style.display = 'block';
                document.getElementById('userBadge').innerText = user;
                
                loadHistory();
                setInterval(loadHistory, 5000);
            }

            function logout() {
                window.location.reload();
            }

            async function loadHistory() {
                if(!currentUser) return;
                const res = await fetch(`/history?username=${currentUser}`);
                const data = await res.json();
                const tbody = document.getElementById('historyTable');
                tbody.innerHTML = '';
                data.forEach(item => {
                    tbody.innerHTML += `
                        <tr style="border-bottom: 1px solid #1e293b;">
                            <td style="padding: 16px;"><strong>${item.target}</strong></td>
                            <td style="padding: 16px;">${item.timestamp}</td>
                            <td style="padding: 16px;"><code>${item.server}</code></td>
                            <td style="padding: 16px;"><span style="padding: 4px 10px; border-radius: 20px; font-weight: bold; background: ${item.grade === 'F' ? '#ef4444' : '#10b981'}">${item.grade}</span></td>
                            <td style="padding: 16px; color: #94a3b8; font-size: 14px;">${item.findings}</td>
                        </tr>
                    `;
                });
            }

            async function startScan() {
                const target = document.getElementById('targetInput').value;
                if(!target) return alert('Target asset domain missing!');
                await fetch(`/scan?target=${target}&username=${currentUser}`);
                alert('Vulnerability scan initialized.');
                setTimeout(loadHistory, 1500);
            }
        </script>
    </body>
    </html>
    """