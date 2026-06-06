from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from app.agent import generate_workflow

app = FastAPI(title="AI Security Incident Responder")
templates = Jinja2Templates(directory="app/templates")


class IncidentRequest(BaseModel):
    incident: str


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/generate")
async def generate(request: IncidentRequest):
    if not request.incident.strip():
        return {"error": "Incident description cannot be empty"}
    result = await generate_workflow(request.incident)
    return result


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "AI Security Incident Responder",
        "data_sources": ["NVD", "MITRE ATT&CK", "CISA KEV"]
    }