from fastapi import FastAPI

app = FastAPI(title="Sentinel Security Scanner", version="0.1.0")


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "sentinel-api"}
