"""Notarized evidence — persistent, re-verifiable chain of custody (Diferenciador #2).

Turns the existing on-demand `evidence_seal` into a *permanent notarial record*:

  1. Seal the scan's critical findings (SHA-256 per finding + a chain hash).
  2. Get a real RFC3161 signed timestamp on the chain hash (FreeTSA).
  3. Persist an **append-only, immutable** record in `db.evidence_notarizations`.
  4. Anyone can later re-verify integrity (INTACT / TAMPERED) and download a
     self-contained evidence bundle admissible for disputes / audits.

This is what makes NOCTUA's evidence "notarized" rather than merely computed.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from integrations.evidence_seal import (
    seal_scan_evidence,
    request_rfc3161_timestamp,
    verify_seal,
    _canonical_json,
)

COLLECTION = "evidence_notarizations"


def _bundle_digest(record: dict) -> str:
    """Deterministic SHA-256 over the notarial payload (excludes volatile fields)."""
    core = {
        "scan_id": record.get("scan_id"),
        "domain": record.get("domain"),
        "chain_hash": record.get("chain_hash"),
        "sealed_findings": record.get("sealed_findings"),
    }
    return hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()


async def notarize(scan_doc: dict, user_id: str, db) -> dict:
    """Seal + timestamp + persist an immutable notarization. Returns a summary."""
    seal = seal_scan_evidence(scan_doc)
    chain_hash = seal["chain_hash"]

    # Real RFC3161 signed timestamp on the chain hash (network call to FreeTSA).
    rfc3161 = await request_rfc3161_timestamp(chain_hash)

    notary_id = f"nz_{uuid.uuid4().hex[:16]}"
    record = {
        "notary_id": notary_id,
        "scan_id": scan_doc.get("scan_id"),
        "user_id": user_id,
        "domain": seal.get("domain"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": seal.get("algorithm"),
        "chain_hash": chain_hash,
        "total_findings_sealed": seal.get("total_findings_sealed", 0),
        "sealed_findings": seal.get("sealed_findings", []),
        "rfc3161_timestamp": rfc3161,
        "custody_note": seal.get("custody_note"),
    }
    record["bundle_sha256"] = _bundle_digest(record)

    # Append-only: never overwrite a prior notarization (each is a point-in-time record).
    await db[COLLECTION].insert_one(dict(record))

    return {
        "notary_id": notary_id,
        "scan_id": record["scan_id"],
        "domain": record["domain"],
        "created_at": record["created_at"],
        "chain_hash": chain_hash,
        "total_findings_sealed": record["total_findings_sealed"],
        "bundle_sha256": record["bundle_sha256"],
        "rfc3161": {
            "ok": rfc3161.get("ok", False),
            "authority": rfc3161.get("authority"),
            "requested_at": rfc3161.get("requested_at"),
            "error": rfc3161.get("error"),
        },
    }


def verify(record: dict) -> dict:
    """Re-derive every hash from the stored findings and confirm nothing changed."""
    meta = {"scan_id": record.get("scan_id"), "domain": record.get("domain")}
    checks: list[dict] = []
    ok = True

    # 1) each finding's per-item hash
    recomputed_hashes = []
    for i, sf in enumerate(record.get("sealed_findings", [])):
        good = verify_seal(sf, meta)
        recomputed_hashes.append(sf.get("sha256"))
        if not good:
            ok = False
            checks.append({"check": f"finding[{i}]", "status": "TAMPERED"})
    if not checks:
        checks.append({"check": "per_finding_hashes", "status": "OK",
                       "count": len(record.get("sealed_findings", []))})

    # 2) chain hash over all finding hashes
    chain_input = _canonical_json(recomputed_hashes)
    chain_recomputed = hashlib.sha256(chain_input.encode()).hexdigest()
    chain_ok = chain_recomputed == record.get("chain_hash")
    ok = ok and chain_ok
    checks.append({"check": "chain_hash", "status": "OK" if chain_ok else "TAMPERED"})

    # 3) bundle digest
    bundle_ok = _bundle_digest(record) == record.get("bundle_sha256")
    ok = ok and bundle_ok
    checks.append({"check": "bundle_sha256", "status": "OK" if bundle_ok else "TAMPERED"})

    # 4) RFC3161 timestamp binds to the chain hash
    tsr = record.get("rfc3161_timestamp") or {}
    tsr_ok = bool(tsr.get("ok")) and tsr.get("sha256_input") == record.get("chain_hash")
    checks.append({
        "check": "rfc3161_timestamp",
        "status": "OK" if tsr_ok else ("MISSING" if not tsr.get("ok") else "MISMATCH"),
        "authority": tsr.get("authority"),
    })

    return {
        "notary_id": record.get("notary_id"),
        "status": "INTACT" if ok else "TAMPERED",
        "timestamped": tsr_ok,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }


def build_bundle(record: dict) -> dict:
    """Self-contained evidence package a third party can verify independently."""
    tsr = record.get("rfc3161_timestamp") or {}
    return {
        "format": "NOCTUA-evidence-bundle/v1",
        "notary_id": record.get("notary_id"),
        "scan_id": record.get("scan_id"),
        "domain": record.get("domain"),
        "created_at": record.get("created_at"),
        "algorithm": record.get("algorithm"),
        "chain_hash": record.get("chain_hash"),
        "bundle_sha256": record.get("bundle_sha256"),
        "total_findings_sealed": record.get("total_findings_sealed"),
        "sealed_findings": record.get("sealed_findings", []),
        "rfc3161_timestamp": {
            "authority": tsr.get("authority"),
            "requested_at": tsr.get("requested_at"),
            "tsr_base64": tsr.get("tsr_base64"),
        },
        "integrity": verify(record),
        "how_to_verify_independently": {
            "1_save_tsr": "Decodifica `rfc3161_timestamp.tsr_base64` (base64) a un archivo tsr.der",
            "2_get_ca": "Descarga la CA de FreeTSA: https://freetsa.org/files/cacert.pem",
            "3_verify": ("openssl ts -verify -digest " + str(record.get("chain_hash")) +
                         " -in tsr.der -CAfile cacert.pem"),
            "note": ("El chain_hash sella todos los hallazgos en orden. Recalcula los SHA-256 de "
                     "`sealed_findings` y compáralos: cualquier alteración rompe el chain_hash y "
                     "la verificación del timestamp."),
        },
    }
