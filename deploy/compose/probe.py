"""Local readiness through the TLS-verified gateway health endpoint."""
import http.client
import json
import ssl
import time

context = ssl.create_default_context(cafile="/run/tls-ca.crt")
context.minimum_version = ssl.TLSVersion.TLSv1_3
for attempt in range(60):
    try:
        gateway = http.client.HTTPSConnection("gateway", 8443, context=context, timeout=3)
        gateway.request("GET", "/health/ready")
        response = gateway.getresponse()
        assert response.status == 200, f"gateway health status: {response.status}"
        state = json.loads(response.read(65536))
        assert state["postgresql"] == "ok" and state["output"] == "ok" and not state["degraded"]
        gateway.close()
        print("Gateway TLS/database/object-storage readiness passed.")
        break
    except (OSError, AssertionError, ValueError, http.client.HTTPException):
        if attempt == 59:
            raise SystemExit("Local gateway readiness timed out.")
        time.sleep(1)
