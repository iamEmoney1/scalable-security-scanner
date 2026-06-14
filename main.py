from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import httpx
import sqlite3
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import asyncio

app = FastAPI()

# ==========================================
# ADVANCED DATABASE SCHEMA (WITH USERS LAYER)
# ==========================================
def init_db():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    # Create Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    """)
    # Create Scans Table linked to a specific user
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
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
# SECURITY DEEP SCANNER ENGINE
# ==========================================
async def run_security_scan(target_url: str, username: str):
    try:
        async with httpx.AsyncClient() as client:
            clean_url = target_url.strip().replace("http://", "").replace("https://", "")
            base_url = f"https://{clean_url}"
            
            response = await client.get(base_url, timeout=5.0, follow_redirects=True)
            headers = response.headers
            
            has_ssl = 1 if response.url.scheme == "https" else 0
            server_name = headers.get('Server', 'Hidden / Protected')
            
            missing_headers = []
            score = 100
            if "X-Frame-Options" not in headers: 
                missing_headers.append("Missing X-Frame-Options")
                score -= 25
            if "Content-Security-Policy" not in headers: 
                missing_headers.append("Missing CSP")
                score -= 30
            if not has_ssl: score -= 30

            if score >= 90: grade = "A"
            elif score >= 75: grade = "B"
            else: grade = "F"
            
            vulns_string = " | ".join(missing_headers) if missing_headers else "None Detected"

            conn = sqlite3.connect("scans.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_results (username, target, timestamp, ssl_active, server, grade, vulnerabilities)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (username, clean_url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), has_ssl, server_name, grade, vulns_string))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Scan failure: {str(e)}")

# ==========================================
# AUTHENTICATION & ROUTING PIPELINES
# ==========================================
@app.post("/register")
async def register_user(username: str = Form(...), password: str = Form(...)):
    try:
        conn = sqlite3.connect("scans.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return HTMLResponse("<script>alert('Account created successfully! You can now log in.'); window.location.href='/';</script>")
    except Exception as e:
        return HTMLResponse("<script>alert('Username already exists! Please try another one.'); window.location.href='/';</script>")

@app.get("/history")
async def get_scan_history(username: str):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, timestamp, ssl_active, server, grade, vulnerabilities FROM scan_results WHERE username = ? ORDER BY id DESC", (username,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "target": r[1], "timestamp": r[2], "ssl_enabled": bool(r[3]), "server": r[4], "grade": r[5], "findings": r[6]} for r in rows]

@app.get("/scan")
async def trigger_scan(target: str, username: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_security_scan, target, username)
    return {"status": "Scan Queued"}

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