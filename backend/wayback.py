"""Wayback Machine (archive.org) integration — free, no API key.

Uses the Availability API (archive.org/wayback/available) which returns the
closest snapshot for a given timestamp. We query multiple probe timestamps
(early years for oldest, recent months for newest) and de-duplicate.
"""
import asyncio
import httpx
from datetime import datetime, timezone, timedelta


AVAIL_URL = "https://archive.org/wayback/available"

OLDEST_PROBES = [
    "19960101", "19970101", "19980101", "19990101",
    "20000101", "20010101", "20020101", "20030101", "20040101",
]


def _newest_probes(n_probes: int = 10) -> list[str]:
    """Recent probes: today, ~1 month ago, 2 months ago... going back ~2 years."""
    today = datetime.now(timezone.utc)
    probes = []
    for i in range(n_probes):
        # spacing: 0, 30, 60, 120, 200, 300, 400, 550, 730, 900 days back
        offsets = [0, 30, 60, 120, 200, 300, 400, 550, 730, 900]
        offset = offsets[i] if i < len(offsets) else 900 + i * 200
        d = today - timedelta(days=offset)
        probes.append(d.strftime("%Y%m%d"))
    return probes


def _parse_ts(ts: str) -> str:
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").isoformat()
    except Exception:
        try:
            return datetime.strptime(ts[:8], "%Y%m%d").isoformat()
        except Exception:
            return ts


async def _probe(client: httpx.AsyncClient, domain: str, ts: str) -> dict | None:
    try:
        r = await client.get(AVAIL_URL, params={"url": domain, "timestamp": ts}, timeout=8.0)
        if r.status_code != 200:
            return None
        data = r.json()
        closest = (data.get("archived_snapshots") or {}).get("closest")
        if not closest or not closest.get("available"):
            return None
        return {
            "timestamp": closest["timestamp"],
            "date": _parse_ts(closest["timestamp"]),
            "snapshot_url": closest["url"].replace("http://web.archive.org", "https://web.archive.org"),
            "status_code": closest.get("status"),
        }
    except Exception:
        return None


async def get_wayback_timeline(domain: str, count: int = 5) -> dict:
    async with httpx.AsyncClient(follow_redirects=True) as c:
        oldest_results, newest_results = await asyncio.gather(
            asyncio.gather(*[_probe(c, domain, ts) for ts in OLDEST_PROBES]),
            asyncio.gather(*[_probe(c, domain, ts) for ts in _newest_probes(10)]),
        )

    def _dedup_sort(items: list, ascending: bool) -> list:
        seen = set()
        out = []
        for s in items:
            if not s:
                continue
            k = s["timestamp"][:8]  # dedupe by day
            if k in seen:
                continue
            seen.add(k)
            out.append(s)
        out.sort(key=lambda x: x["timestamp"], reverse=not ascending)
        return out

    oldest = _dedup_sort(oldest_results, ascending=True)[:count]
    newest_all = _dedup_sort(newest_results, ascending=False)

    # exclude any dates already present in oldest to avoid overlap on new domains
    oldest_days = {s["timestamp"][:8] for s in oldest}
    newest = [s for s in newest_all if s["timestamp"][:8] not in oldest_days][:count]

    return {
        "domain": domain,
        "oldest": oldest,
        "newest": newest,
        "total_returned": len(oldest) + len(newest),
    }
