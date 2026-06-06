PROJECT_NAME = "Threat Intelligence Platform"


import ipaddress
import re
from datetime import datetime

HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

KNOWN_BAD = {
    "malicious.example": ("critical", "Known malware command and control domain in demo feed."),
    "198.51.100.66": ("high", "Demo threat feed IP associated with credential phishing infrastructure."),
    "44d88612fea8a8f36de82e1278abb02f": ("critical", "EICAR test hash style malware indicator.")
}

def indicator_type(value):
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(value):
        return "hash"
    if DOMAIN_RE.match(value):
        return "domain"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    return "unknown"

def analyze(payload):
    indicators = payload.get("indicators") or payload.get("iocs") or []
    if isinstance(indicators, str):
        indicators = [line.strip() for line in indicators.splitlines() if line.strip()]
    results = []
    for ioc in indicators:
        clean = ioc.strip()
        ioc_type = indicator_type(clean)
        severity, note = KNOWN_BAD.get(clean.lower(), ("low", "No local feed match. Enrich with VirusTotal or MISP in production."))
        if ioc_type == "unknown":
            severity = "info"
            note = "Indicator format is unknown. Validate before ingestion."
        results.append({
            "indicator": clean,
            "type": ioc_type,
            "severity": severity,
            "confidence": 90 if clean.lower() in KNOWN_BAD else 35,
            "source": "local-demo-feed",
            "note": note
        })
    return {
        "ioc_count": len(results),
        "results": results,
        "score": min(100, sum(30 if r["severity"] == "critical" else 20 if r["severity"] == "high" else 5 for r in results)),
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

