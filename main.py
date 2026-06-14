from fastapi import FastAPI, BackgroundTasks
import httpx
import sqlite3
from datetime import datetime

app = FastAPI()

# Automatically set up the database file and table on launch
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
    print(f"\n[WORKER] Running scan and saving to database for: {target_url}")
    try:
        async with httpx.AsyncClient() as client:
            url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
            response = await client.get(url, timeout=5.0)
            headers = response.headers
            
            has_ssl = 1 if response.url.scheme == "https" else 0
            server_name = headers.get('Server', 'Hidden/Unknown')
            
            missing_headers = []
            if "X-Frame-Options" not in headers: missing_headers.append("Missing X-Frame-Options")
            if "Content-Security-Policy" not in headers: missing_headers.append("Missing CSP")
            
            vulns_string = ", ".join(missing_headers) if missing_headers else "None Detected"

            # SAVE TO DATABASE
            conn = sqlite3.connect("scans.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_results (target, timestamp, ssl_active, server, vulnerabilities)
                VALUES (?, ?, ?, ?, ?)
            """, (target_url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), has_ssl, server_name, vulns_string))
            conn.commit()
            conn.close()
            
            print(f"[DATABASE] Scan for {target_url} successfully written to storage.")
                
    except Exception as e:
        print(f"[WORKER] Database save failed. Error: {str(e)}")

@app.get("/scan")
async def trigger_scan(target: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_security_scan, target)
    return {"status": "Scan Queued", "target": target}

# NEW ENDPOINT: Let's view the saved database history
@app.get("/history")
async def get_scan_history():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, timestamp, ssl_active, server, vulnerabilities FROM scan_results ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    
    # Format the data cleanly for the browser response
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "target": row[1],
            "timestamp": row[2],
            "ssl_enabled": bool(row[3]),
            "server": row[4],
            "findings": row[5]
        })
    return {"total_scans": len(history), "history": history}