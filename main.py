from fastapi import FastAPI, BackgroundTasks
import httpx

app = FastAPI()

async def run_security_scan(target_url: str):
    print(f"[WORKER] Starting automated scan on: {target_url}")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://{target_url}", timeout=5.0)
            headers = response.headers
            has_ssl = response.url.scheme == "https"
            server_type = headers.get("Server", "Unknown")
            print(f"[WORKER] Scan Complete. SSL: {has_ssl}, Server: {server_type}")
    except Exception as e:
        print(f"[WORKER] Scan failed. Error: {str(e)}")

@app.get("/scan")
async def trigger_scan(target: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_security_scan, target)
    return {
        "status": "Scan Queued",
        "target_received": target,
        "message": "The automated engine is analyzing this asset in the background."
    }