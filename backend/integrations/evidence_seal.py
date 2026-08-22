"""Evidence Sealing — SHA-256 hash + RFC3161-style timestamp for critical findings."""
import hashlib
import json
import logging
import base64
import httpx
from datetime import datetime, timezone

log = logging.getLogger("evidence")

FREETSA_URL = "https://freetsa.org/tsr"


def _canonical_json(obj) -> str:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _seal_finding(finding: dict, scan_meta: dict) -> dict:
    """Compute SHA-256 hash + UTC timestamp for a single finding.

    IMPORTANT: `sealed_at` uses the scan's `scanned_at` (creation timestamp) so
    that re-sealing the SAME scan produces IDENTICAL hashes — required for
    chain-of-custody integrity. If scan has no created_at, falls back to now().
    """
    ts = scan_meta.get("scanned_at") or datetime.now(timezone.utc).isoformat()
    payload = {
        "finding": finding,
        "scan_id": scan_meta.get("scan_id"),
        "domain": scan_meta.get("domain"),
        "sealed_at": ts,
    }
    canonical = _canonical_json(payload)
    sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "sealed_at": ts,
        "sha256": sha256,
        "canonical_length": len(canonical),
        "finding": finding,
    }


def seal_scan_evidence(scan_doc: dict) -> dict:
    """Extract critical findings from ALL modules and seal each with hash+timestamp."""
    scan_id = scan_doc.get("scan_id")
    domain = (scan_doc.get("result") or {}).get("domain")
    meta = {"scan_id": scan_id, "domain": domain,
            "scanned_at": scan_doc.get("created_at")}

    sealed: list[dict] = []

    # Takeover vulnerabilities
    for r in ((scan_doc.get("result", {}).get("takeover") or {}).get("results") or []) + \
             ((scan_doc.get("takeover") or {}).get("results") or []):
        if r.get("vulnerable"):
            sealed.append(_seal_finding({
                "type": "subdomain_takeover",
                "subdomain": r.get("subdomain"),
                "service": r.get("service"),
                "evidence": r.get("evidence"),
                "severity": "critical",
            }, meta))

    # Open cloud buckets
    for b in ((scan_doc.get("cloud") or {}).get("open") or []):
        if b.get("listable"):
            sealed.append(_seal_finding({
                "type": "open_cloud_bucket",
                "provider": b.get("kind"),
                "name": b.get("name"), "url": b.get("url"),
                "severity": "critical",
            }, meta))

    # Cloud config leaks
    for f in ((scan_doc.get("cloud_config") or {}).get("findings") or []):
        if f.get("severity") in ("critical", "high"):
            sealed.append(_seal_finding({
                "type": "config_leak",
                "path": f.get("path"), "url": f.get("url"),
                "content_preview": (f.get("content_preview") or "")[:200],
                "confirmed": f.get("confirmed", False),
                "severity": f.get("severity"),
            }, meta))

    # JS Miner secrets
    for f in ((scan_doc.get("js_miner") or {}).get("findings") or []):
        if f.get("severity") == "critical":
            sealed.append(_seal_finding({
                "type": "leaked_secret",
                "kind": f.get("kind"),
                "match": (f.get("match") or "")[:100],
                "source": f.get("source"),
                "severity": "critical",
            }, meta))

    # Shodan deep critical alerts
    for host in ((scan_doc.get("shodan_deep") or {}).get("hosts") or []):
        for a in (host.get("alerts") or []):
            if a.get("severity") == "critical":
                sealed.append(_seal_finding({
                    "type": "unauth_service_exposed",
                    "ip": host.get("ip"), "port": a.get("port"),
                    "service": a.get("service"), "flag": a.get("flag"),
                    "severity": "critical",
                }, meta))

    # Supply chain critical CVEs
    for lib in ((scan_doc.get("supply_chain") or {}).get("vulnerable_libraries") or []):
        if lib.get("worst_severity") == "critical":
            for v in (lib.get("vulnerabilities") or []):
                if v.get("severity") == "critical":
                    sealed.append(_seal_finding({
                        "type": "vulnerable_library",
                        "library": lib.get("name"), "version": lib.get("version"),
                        "cve_id": v.get("id"), "cves": v.get("cves"),
                        "cvss_score": v.get("cvss_score"),
                        "severity": "critical",
                    }, meta))
                    break  # only seal worst CVE per lib

    # Chain hash: root SHA-256 that seals the entire evidence pack.
    # This is deterministic across re-seals of the same scan state because
    # each finding's sha256 uses scan.created_at (not now()).
    chain_input = _canonical_json([e["sha256"] for e in sealed])
    chain_hash = hashlib.sha256(chain_input.encode()).hexdigest()

    return {
        "scan_id": scan_id, "domain": domain,
        "sealed_at": meta.get("scanned_at") or datetime.now(timezone.utc).isoformat(),
        "total_findings_sealed": len(sealed),
        "chain_hash": chain_hash,
        "algorithm": "SHA-256 over canonical JSON",
        "custody_note": ("Cada hallazgo está sellado con SHA-256 + timestamp UTC. "
                         "El chain_hash concatena todos los hashes en orden — cualquier alteración "
                         "posterior invalidaría la cadena. Adecuado para reportes legales/auditorías."),
        "sealed_findings": sealed,
    }


def verify_seal(sealed_finding: dict, scan_meta: dict) -> bool:
    """Re-compute the hash and compare — returns True if unchanged."""
    payload = {
        "finding": sealed_finding.get("finding"),
        "scan_id": scan_meta.get("scan_id"),
        "domain": scan_meta.get("domain"),
        "sealed_at": sealed_finding.get("sealed_at"),
    }
    canonical = _canonical_json(payload)
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return expected == sealed_finding.get("sha256")


async def request_rfc3161_timestamp(sha256_hex: str) -> dict:
    """Request a real RFC3161 timestamp for a given SHA-256 digest from FreeTSA.org.

    Builds a minimal ASN.1 TimeStampReq (RFC 3161 §2.4.1) containing our
    SHA-256 digest and posts it to FreeTSA. The signed TimeStampResp is
    returned as base64 for storage + independent verification.
    """
    try:
        digest = bytes.fromhex(sha256_hex)
        if len(digest) != 32:
            return {"ok": False, "error": "SHA-256 digest must be 32 bytes"}

        # Hand-rolled minimal DER encoding of a TimeStampReq (avoids adding
        # a full cryptography/asn1crypto dep for one endpoint):
        #   TimeStampReq ::= SEQUENCE {
        #     version           INTEGER (1),
        #     messageImprint    SEQUENCE {
        #       hashAlgorithm   AlgorithmIdentifier,
        #       hashedMessage   OCTET STRING
        #     },
        #     certReq           BOOLEAN (TRUE)
        #   }
        def _tlv(tag: int, value: bytes) -> bytes:
            if len(value) < 0x80:
                return bytes([tag, len(value)]) + value
            length_bytes = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
            return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + value

        # OID 2.16.840.1.101.3.4.2.1 = SHA-256
        sha256_oid = bytes.fromhex("608648016503040201")
        alg_id = _tlv(0x30, _tlv(0x06, sha256_oid) + _tlv(0x05, b""))  # AlgorithmIdentifier
        message_imprint = _tlv(0x30, alg_id + _tlv(0x04, digest))
        version = _tlv(0x02, b"\x01")
        cert_req = _tlv(0x01, b"\xff")
        ts_req = _tlv(0x30, version + message_imprint + cert_req)

        async with httpx.AsyncClient(timeout=12.0) as c:
            r = await c.post(FREETSA_URL, content=ts_req,
                             headers={"Content-Type": "application/timestamp-query",
                                      "User-Agent": "NOCTUA-osint"})
        if r.status_code != 200:
            return {"ok": False, "error": f"FreeTSA HTTP {r.status_code}",
                    "detail": r.text[:200] if r.text else ""}
        return {
            "ok": True,
            "authority": "FreeTSA.org",
            "sha256_input": sha256_hex,
            "tsr_size_bytes": len(r.content),
            "tsr_base64": base64.b64encode(r.content).decode("ascii"),
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "verification_note": ("Guarda el tsr_base64 para verificación futura con: "
                                   "`openssl ts -verify -in tsr.der -digest <sha256> -CAfile freetsa-ca.pem`. "
                                   "FreeTSA CA disponible en https://freetsa.org/files/cacert.pem"),
        }
    except Exception as e:
        log.warning(f"RFC3161 timestamp failed: {e}")
        return {"ok": False, "error": str(e)}
