"""Create and verify the isolated SeaweedFS demo bucket using signed S3 APIs."""
import datetime
import hashlib
import hmac
import http.client
import json
import secrets
import time
import xml.etree.ElementTree as ET
from pathlib import Path

HOST = "seaweedfs:8333"
BUCKET = "allowops-demo"
credentials = json.loads(Path("/run/secrets/s3.json").read_text())["identities"][0]["credentials"][0]


def request(method, path, body=b""):
    # AWS Signature Version 4; the local demo uses path-style S3 and no query strings.
    now = datetime.datetime.now(datetime.timezone.utc)
    date = now.strftime("%Y%m%d")
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {"host": HOST, "x-amz-content-sha256": payload_hash, "x-amz-date": timestamp}
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
    canonical = "\n".join((method, path, "", canonical_headers, signed_headers, payload_hash))
    scope = f"{date}/us-east-1/s3/aws4_request"
    to_sign = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()))
    key = ("AWS4" + credentials["secretKey"]).encode()
    for value in (date, "us-east-1", "s3", "aws4_request"):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={credentials['accessKey']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    connection = http.client.HTTPConnection("seaweedfs", 8333, timeout=5)
    try:
        connection.request(method, path, body, headers)
        response = connection.getresponse()
        data = response.read(1048576)
        if not 200 <= response.status < 300:
            code = ET.fromstring(data).findtext("Code")
            if method == "PUT" and path == f"/{BUCKET}" and code == "BucketAlreadyOwnedByYou":
                return data
            raise RuntimeError(f"S3 {method} {path}: HTTP {response.status}, code={code}")
        return data
    finally:
        connection.close()


for attempt in range(60):
    try:
        request("GET", "/")
        request("PUT", f"/{BUCKET}")
        path = f"/{BUCKET}/quickstart-check.txt"
        payload = b"Allowops local S3 demonstration\n" + secrets.token_hex(16).encode()
        request("PUT", path, payload)
        assert request("GET", path) == payload, "S3 object readback differs from the uploaded bytes"
        request("DELETE", path)
        print(f"PASS: SeaweedFS S3 bucket {BUCKET} created; object write/read/delete verified ({len(payload)} bytes).")
        break
    except (OSError, RuntimeError, http.client.HTTPException, ET.ParseError) as error:
        if attempt == 59:
            raise SystemExit(f"Local S3 initialization timed out: {error}") from None
        time.sleep(1)
