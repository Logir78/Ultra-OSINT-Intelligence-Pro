"""Document metadata extractor — Metagoofil-style OSINT.
Finds recent PDF/DOCX/XLSX indexed for a domain via DuckDuckGo, downloads them,
extracts authors, creator software, timestamps, and internal paths.
"""
import asyncio
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse
import httpx
import logging

from integrations.stealth import stealth_httpx_client

log = logging.getLogger("metadata")

DDG_HTML = "https://html.duckduckgo.com/html/"
FILE_TYPES = ("pdf", "docx", "xlsx", "doc", "xls", "pptx")

OBSOLETE_HINTS = [
    ("Office 2003", ("Microsoft Word 11", "Excel 11", "PowerPoint 11")),
    ("Office 2007", ("Microsoft Office Word 2007", "Excel 12.0", "Word 12")),
    ("Office 2010", ("Word 14", "Excel 14")),
    ("Office 2013 or older", ("Word 15", "Excel 15")),
    ("Adobe Acrobat 9 or older", ("Acrobat 9",)),
    ("OpenOffice", ("OpenOffice",)),
    ("LibreOffice 4-5 (obsoleto)", ("LibreOffice 4", "LibreOffice 5")),
    ("Windows XP era", ("Windows NT 5",)),
    ("Windows 7 era", ("Windows NT 6.1",)),
]

EMPLOYEE_PATTERNS = [
    re.compile(r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b"),  # "John Smith"
]


async def _ddg_search(client: httpx.AsyncClient, query: str) -> list[str]:
    """Return URLs from a DDG HTML search."""
    try:
        r = await client.post(DDG_HTML, data={"q": query}, timeout=12.0)
        html = r.text
    except Exception as e:
        log.warning(f"DDG search failed: {e}")
        return []
    urls = re.findall(r'href="(?:/l/\?[^"]*uddg=)?(https?%3A%2F%2F[^"&]+|https?://[^"]+?)"', html)
    out = []
    for u in urls:
        if u.startswith("http") and any(u.lower().endswith(f".{ft}") for ft in FILE_TYPES):
            # decode url-encoded links
            try:
                from urllib.parse import unquote
                u = unquote(u)
            except Exception:
                pass
            if u not in out:
                out.append(u)
        if len(out) >= 15:
            break
    return out


async def _fetch_bytes(client: httpx.AsyncClient, url: str, max_mb: int = 8) -> bytes | None:
    try:
        async with client.stream("GET", url, timeout=20.0, follow_redirects=True) as r:
            if r.status_code != 200:
                return None
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_mb * 1024 * 1024:
                    return None
            return bytes(buf)
    except Exception as e:
        log.warning(f"fetch fail {url}: {e}")
        return None


def _extract_pdf_meta(data: bytes) -> dict:
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(data))
        info = reader.metadata or {}
        return {
            "author": str(info.get("/Author", "")) or None,
            "creator": str(info.get("/Creator", "")) or None,
            "producer": str(info.get("/Producer", "")) or None,
            "title": str(info.get("/Title", "")) or None,
            "subject": str(info.get("/Subject", "")) or None,
            "creation_date": str(info.get("/CreationDate", "")) or None,
            "mod_date": str(info.get("/ModDate", "")) or None,
            "pages": len(reader.pages),
        }
    except Exception as e:
        return {"error": str(e)}


def _extract_office_meta(data: bytes) -> dict:
    """DOCX/XLSX/PPTX use zip + docProps/core.xml + app.xml."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            meta = {}
            paths = set()
            for name in z.namelist():
                paths.add(name.split("/")[0] if "/" in name else name)
                if name == "docProps/core.xml":
                    tree = ET.fromstring(z.read(name))
                    ns = {"dc": "http://purl.org/dc/elements/1.1/",
                          "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                          "dcterms": "http://purl.org/dc/terms/"}
                    meta["author"] = _findtxt(tree, "dc:creator", ns)
                    meta["last_modified_by"] = _findtxt(tree, "cp:lastModifiedBy", ns)
                    meta["title"] = _findtxt(tree, "dc:title", ns)
                    meta["subject"] = _findtxt(tree, "dc:subject", ns)
                    meta["description"] = _findtxt(tree, "dc:description", ns)
                    meta["creation_date"] = _findtxt(tree, "dcterms:created", ns)
                    meta["mod_date"] = _findtxt(tree, "dcterms:modified", ns)
                elif name == "docProps/app.xml":
                    tree = ET.fromstring(z.read(name))
                    ns = {"e": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
                    meta["creator"] = _findtxt(tree, "e:Application", ns)
                    meta["app_version"] = _findtxt(tree, "e:AppVersion", ns)
                    meta["company"] = _findtxt(tree, "e:Company", ns)
                    meta["template"] = _findtxt(tree, "e:Template", ns)
            return meta
    except Exception as e:
        return {"error": str(e)}


def _findtxt(tree, path, ns):
    el = tree.find(path, ns)
    return (el.text or "").strip() if el is not None and el.text else None


def _analyze_warnings(meta: dict, all_meta: list[dict]) -> list[str]:
    warns = []
    creator = " ".join(str(v or "") for v in [meta.get("creator"), meta.get("producer")])
    for label, patterns in OBSOLETE_HINTS:
        if any(p.lower() in creator.lower() for p in patterns):
            warns.append(f"Software obsoleto detectado: {label}")
    for field in ("author", "last_modified_by"):
        v = meta.get(field)
        if v and EMPLOYEE_PATTERNS[0].match(v.strip()):
            warns.append(f"Posible nombre de empleado expuesto: {v}")
    return warns


async def extract_domain_docs(domain: str, max_docs: int = 10) -> dict:
    query_parts = " OR ".join(f"filetype:{ft}" for ft in FILE_TYPES)
    query = f'site:{domain} ({query_parts})'
    async with stealth_httpx_client(domain) as client:
        urls = await _ddg_search(client, query)
        urls = urls[:max_docs]
        docs: list[dict] = []
        for url in urls:
            data = await _fetch_bytes(client, url)
            if not data:
                docs.append({"url": url, "reachable": False})
                continue
            ext = url.rsplit(".", 1)[-1].lower()
            meta = _extract_pdf_meta(data) if ext == "pdf" else _extract_office_meta(data)
            meta_full = {"url": url, "filename": urlparse(url).path.split("/")[-1] or url,
                         "type": ext, "reachable": True, "size_bytes": len(data),
                         "metadata": meta}
            meta_full["warnings"] = _analyze_warnings(meta, docs)
            docs.append(meta_full)

    all_authors = sorted({
        d["metadata"].get("author") for d in docs
        if d.get("metadata") and d["metadata"].get("author")
    })
    all_software = sorted({
        v for d in docs if d.get("metadata")
        for v in [d["metadata"].get("creator"), d["metadata"].get("producer")]
        if v
    })
    return {
        "domain": domain,
        "query": query,
        "found": len(docs),
        "reachable": sum(1 for d in docs if d.get("reachable")),
        "docs": docs,
        "unique_authors": all_authors,
        "unique_software": all_software,
    }
