import { useMemo, useEffect, useState } from "react";
import { ReactFlow, Background, Controls, MiniMap, MarkerType } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import axios from "axios";
import { Loader2 } from "lucide-react";
import { API } from "@/lib/auth";

/* ------------ Custom node ------------ */
const NODE_STYLES = {
  domain:      { color: "#00E5FF", bg: "#0A0A0C", size: 90,  label: "DOMINIO" },
  subdomain:   { color: "#39FF14", bg: "#050506", size: 60,  label: "SUB" },
  ip:          { color: "#4C8BFF", bg: "#050506", size: 55,  label: "IP" },
  certificate: { color: "#FFAA00", bg: "#050506", size: 55,  label: "CERT" },
  isp:         { color: "#FF3355", bg: "#050506", size: 65,  label: "ISP" },
};

function IntelNode({ data }) {
  const s = NODE_STYLES[data.kind] || NODE_STYLES.subdomain;
  const size = s.size;
  return (
    <div
      data-testid={`node-${data.kind}-${data.label}`}
      className="flex items-center justify-center font-mono-data text-center"
      style={{
        width: size, height: size,
        border: `2px solid ${s.color}`,
        background: s.bg,
        color: s.color,
        borderRadius: data.kind === "domain" ? "50%" : "6px",
        boxShadow: `0 0 22px ${s.color}55, inset 0 0 12px ${s.color}22`,
        fontSize: data.kind === "domain" ? 11 : 9,
        fontWeight: 700,
        padding: 6,
        lineHeight: 1.2,
        wordBreak: "break-all",
      }}
      title={data.tooltip}
    >
      {data.label}
    </div>
  );
}

const nodeTypes = { intel: IntelNode };

/* ------------ Graph builder ------------ */
function buildGraph(result, geoip) {
  const nodes = [];
  const edges = [];
  const seen = new Set();
  const add = (id, node) => { if (!seen.has(id)) { seen.add(id); nodes.push({ id, ...node }); } };

  const domain = result.domain;
  // radial layout
  const cx = 500, cy = 400;

  add(`d:${domain}`, {
    type: "intel",
    data: { kind: "domain", label: domain, tooltip: `Dominio raíz: ${domain}` },
    position: { x: cx, y: cy },
  });

  // IP nodes (main + subdomains)
  const ips = new Map();  // ip -> { hostnames: Set, isp: str, country: str }
  const mainIp = result.ip?.ip;
  if (mainIp) ips.set(mainIp, { hostnames: new Set([domain]), isp: null });
  for (const s of (result.subdomains?.found || [])) {
    for (const ip of s.ips || []) {
      if (!ips.has(ip)) ips.set(ip, { hostnames: new Set(), isp: null });
      ips.get(ip).hostnames.add(s.subdomain);
    }
  }
  // enrich with geoip
  for (const g of (geoip || [])) {
    if (g.success && ips.has(g.ip)) {
      ips.get(g.ip).isp = g.isp;
      ips.get(g.ip).country = g.country;
    }
  }

  const ipArr = Array.from(ips.entries());
  const ipRadius = 220;
  ipArr.forEach(([ip, meta], i) => {
    const angle = (i / Math.max(ipArr.length, 1)) * 2 * Math.PI;
    const id = `ip:${ip}`;
    add(id, {
      type: "intel",
      data: {
        kind: "ip", label: ip,
        tooltip: `${ip}${meta.isp ? " · " + meta.isp : ""}${meta.country ? " · " + meta.country : ""}`,
      },
      position: { x: cx + Math.cos(angle) * ipRadius, y: cy + Math.sin(angle) * ipRadius },
    });
  });

  // Subdomain nodes on outer ring
  const subs = result.subdomains?.found || [];
  const subRadius = 400;
  subs.forEach((s, i) => {
    const angle = (i / Math.max(subs.length, 1)) * 2 * Math.PI + 0.2;
    const id = `s:${s.subdomain}`;
    add(id, {
      type: "intel",
      data: { kind: "subdomain", label: s.subdomain.replace(`.${domain}`, ""), tooltip: s.subdomain },
      position: { x: cx + Math.cos(angle) * subRadius, y: cy + Math.sin(angle) * subRadius },
    });
    // edge subdomain → each of its IPs
    for (const ip of s.ips || []) {
      edges.push({
        id: `${id}->ip:${ip}`, source: id, target: `ip:${ip}`,
        animated: true, style: { stroke: "#39FF1466", strokeWidth: 1 },
      });
    }
  });

  // Edge from domain to its main IP
  if (mainIp) {
    edges.push({
      id: `d:${domain}->ip:${mainIp}`, source: `d:${domain}`, target: `ip:${mainIp}`,
      animated: true, style: { stroke: "#00E5FFAA", strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#00E5FF" },
    });
  }

  // Certificate node (SAN)
  const san = result.ssl?.san || [];
  if (san.length > 0) {
    add("cert", {
      type: "intel",
      data: {
        kind: "certificate",
        label: `SSL\n${san.length} SAN`,
        tooltip: `Cert emitido por ${result.ssl?.issuer?.organizationName || "?"} · SAN: ${san.slice(0, 5).join(", ")}`,
      },
      position: { x: cx - 260, y: cy - 260 },
    });
    edges.push({
      id: `d:${domain}->cert`, source: `d:${domain}`, target: "cert",
      style: { stroke: "#FFAA0080", strokeWidth: 1.5, strokeDasharray: "4 3" },
    });
  }

  // ISP grouping — connect IPs that share the same ISP with an ISP node
  const ispToIps = new Map();
  for (const [ip, meta] of ipArr) {
    if (!meta.isp) continue;
    if (!ispToIps.has(meta.isp)) ispToIps.set(meta.isp, []);
    ispToIps.get(meta.isp).push(ip);
  }
  const ispArr = Array.from(ispToIps.entries()).filter(([, arr]) => arr.length >= 1);
  ispArr.forEach(([isp, ipList], i) => {
    const angle = (i / Math.max(ispArr.length, 1)) * 2 * Math.PI + 0.5;
    const id = `isp:${isp}`;
    add(id, {
      type: "intel",
      data: {
        kind: "isp",
        label: isp.length > 18 ? isp.slice(0, 16) + "…" : isp,
        tooltip: `ISP: ${isp} — ${ipList.length} IP(s)`,
      },
      position: { x: cx + Math.cos(angle) * 80, y: cy + Math.sin(angle) * 80 },
    });
    for (const ip of ipList) {
      edges.push({
        id: `${id}->ip:${ip}`, source: id, target: `ip:${ip}`,
        style: { stroke: "#FF335566", strokeWidth: 1, strokeDasharray: "2 4" },
      });
    }
  });

  return { nodes, edges, stats: { ips: ipArr.length, subdomains: subs.length, isps: ispArr.length, san: san.length } };
}

export default function IntelligenceMap({ scan, scanId }) {
  const [geoip, setGeoip] = useState(null);
  const [loadingGeo, setLoadingGeo] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/geoip`, { withCredentials: true, timeout: 45000 });
        setGeoip(r.data.geoip || []);
      } catch (_) { /* enrichment only */ } finally { setLoadingGeo(false); }
    })();
  }, [scanId]);

  const { nodes, edges, stats } = useMemo(
    () => buildGraph(scan, geoip || []),
    [scan, geoip]
  );

  return (
    <div data-testid="intelligence-map" className="border border-white/[0.06] bg-[#0A0A0C] mb-5">
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-white/[0.06] bg-[#101014]">
        <h3 className="font-heading text-sm font-bold tracking-wide uppercase">
          Mapa de Inteligencia · Red del dominio
        </h3>
        <div className="flex items-center gap-3 font-mono-data text-[10px] uppercase tracking-widest text-white/40">
          <span>{stats.ips} IPs</span>
          <span>{stats.subdomains} subs</span>
          <span>{stats.isps} ISPs</span>
          {stats.san > 0 && <span>{stats.san} SAN</span>}
          {loadingGeo && <Loader2 className="w-3 h-3 animate-spin text-cyan-400" />}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 px-5 py-2.5 border-b border-white/[0.06] bg-[#050506]">
        {Object.entries(NODE_STYLES).map(([k, v]) => (
          <div key={k} className="flex items-center gap-2">
            <span style={{ background: v.color, width: 10, height: 10, borderRadius: k === "domain" ? "50%" : "2px", boxShadow: `0 0 8px ${v.color}` }} />
            <span className="font-mono-data text-[10px] uppercase tracking-widest text-white/60">{v.label}</span>
          </div>
        ))}
      </div>

      <div style={{ height: 620, background: "#000" }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.2}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
          nodesDraggable
        >
          <Background color="#1a1a20" gap={24} size={1} />
          <Controls className="!bg-[#0A0A0C] !border !border-white/10 [&_button]:!bg-transparent [&_button]:!text-cyan-400 [&_button]:!border-white/10" />
          <MiniMap
            style={{ background: "#050506", border: "1px solid rgba(255,255,255,0.08)" }}
            maskColor="rgba(0,0,0,0.85)"
            nodeColor={(n) => NODE_STYLES[n.data?.kind]?.color || "#666"}
          />
        </ReactFlow>
      </div>
    </div>
  );
}
