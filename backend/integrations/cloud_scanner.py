"""Cloud storage bucket enumerator — passive detection of S3 / Azure Blob / GCS.
No API keys needed. Uses public HTTP probes only.
"""
import asyncio
import re
import httpx
from typing import Any


PROVIDERS = ["s3", "azure", "gcs"]


def _base_name(domain: str) -> str:
    return re.sub(r"[^a-z0-9-]", "", domain.lower().split(".")[0])


def generate_candidates(domain: str, extra: list[str] | None = None) -> list[str]:
    """Generate common bucket-name permutations for a domain."""
    base = _base_name(domain)
    tld_less = re.sub(r"\..*$", "", domain.lower())
    seeds = list({base, tld_less, domain.replace(".", "-"), domain.replace(".", "")})
    if extra:
        seeds.extend(extra)

    suffixes = [
        "", "-prod", "-production", "-staging", "-stage", "-dev", "-development",
        "-test", "-qa", "-uat", "-backup", "-backups", "-bkp", "-data", "-static",
        "-assets", "-media", "-images", "-uploads", "-files", "-public", "-private",
        "-internal", "-logs", "-archive", "-old", "-new", "-www", "-cdn", "-tmp",
    ]
    prefixes = ["", "backup-", "prod-", "dev-", "static-", "media-", "files-"]

    out = set()
    for seed in seeds:
        for p in prefixes:
            for s in suffixes:
                name = f"{p}{seed}{s}"
                if 3 <= len(name) <= 63 and re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", name):
                    out.add(name)
    return sorted(out)


def _classify_s3(status: int, text: str) -> dict:
    if status == 200:
        # bucket exists AND is publicly listable
        return {"exists": True, "public": True, "listable": True, "note": "Listing público"}
    if status == 403:
        # exists but restricted
        return {"exists": True, "public": False, "listable": False, "note": "Existe (403)"}
    if status == 404 and "NoSuchBucket" in text:
        return {"exists": False, "public": False, "listable": False}
    if status == 301:
        return {"exists": True, "public": False, "listable": False, "note": "Redirect (existe)"}
    return {"exists": False, "public": False, "listable": False}


def _classify_azure(status: int) -> dict:
    if status == 200:
        return {"exists": True, "public": True, "listable": True, "note": "Container público"}
    if status in (400, 409):
        return {"exists": True, "public": False, "listable": False, "note": "Existe pero restringido"}
    return {"exists": False, "public": False, "listable": False}


def _classify_gcs(status: int) -> dict:
    if status == 200:
        return {"exists": True, "public": True, "listable": True, "note": "Bucket público"}
    if status == 403:
        return {"exists": True, "public": False, "listable": False, "note": "Existe (403)"}
    return {"exists": False, "public": False, "listable": False}


async def _probe(client: httpx.AsyncClient, name: str, provider: str) -> dict | None:
    try:
        if provider == "s3":
            url = f"https://{name}.s3.amazonaws.com/"
            r = await client.get(url, timeout=6.0)
            info = _classify_s3(r.status_code, r.text[:300])
            info["url"] = url
        elif provider == "azure":
            # list containers via anonymous restype=container endpoint
            url = f"https://{name}.blob.core.windows.net/?restype=account&comp=list"
            r = await client.get(url, timeout=6.0)
            info = _classify_azure(r.status_code)
            info["url"] = f"https://{name}.blob.core.windows.net/"
        else:  # gcs
            url = f"https://storage.googleapis.com/{name}/"
            r = await client.get(url, timeout=6.0)
            info = _classify_gcs(r.status_code)
            info["url"] = url
        if not info.get("exists"):
            return None
        info.update({"name": name, "provider": provider, "status_code": r.status_code})
        return info
    except Exception:
        return None


async def scan_cloud_storage(domain: str, max_candidates: int = 40) -> dict[str, Any]:
    candidates = generate_candidates(domain)[:max_candidates]
    limits = httpx.Limits(max_connections=30, max_keepalive_connections=10)
    async with httpx.AsyncClient(limits=limits, follow_redirects=False) as client:
        tasks = []
        for name in candidates:
            for provider in PROVIDERS:
                tasks.append(_probe(client, name, provider))
        results = await asyncio.gather(*tasks)

    hits = [r for r in results if r]
    public = [r for r in hits if r.get("public")]
    return {
        "domain": domain,
        "candidates_checked": len(candidates) * len(PROVIDERS),
        "hits": hits,
        "public_count": len(public),
        "provider_summary": {
            p: {"total": sum(1 for h in hits if h["provider"] == p),
                "public": sum(1 for h in hits if h["provider"] == p and h.get("public"))}
            for p in PROVIDERS
        },
    }
