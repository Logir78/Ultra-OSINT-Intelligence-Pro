import { useEffect, useState } from "react";
import axios from "axios";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { X, MapPin, Loader2, Server, Globe2 } from "lucide-react";
import { toast } from "sonner";
import { API } from "@/lib/auth";

// Fix default marker icons in Leaflet with webpack
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
  iconUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
  shadowUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
});

export default function ServerMapModal({ scanId, onClose }) {
  const [geoip, setGeoip] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const r = await axios.get(`${API}/scans/${scanId}/geoip`, { withCredentials: true });
        setGeoip(r.data.geoip || []);
      } catch (e) {
        toast.error("No se pudo cargar la geolocalización");
      } finally {
        setLoading(false);
      }
    })();
  }, [scanId]);

  // Close on escape
  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const valid = (geoip || []).filter((g) => g.success && g.latitude && g.longitude);
  const center = valid.length ? [valid[0].latitude, valid[0].longitude] : [20, 0];

  return (
    <div
      data-testid="server-map-modal"
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-6xl h-[85vh] bg-[#0C0C0E] border border-cyan-400/40 flex flex-col"
        style={{ boxShadow: "0 0 60px rgba(0,229,255,0.1)" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* HEADER */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10">
          <div className="flex items-center gap-3">
            <Globe2 className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="font-heading text-lg font-bold tracking-tight">Mapa de Servidores</h2>
              <p className="font-mono-data text-[10px] uppercase tracking-widest text-white/40">
                {valid.length} IP{valid.length !== 1 ? "s" : ""} geolocalizada{valid.length !== 1 ? "s" : ""}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            data-testid="close-map-modal"
            className="border border-white/15 p-2 hover:border-red-400 hover:text-red-400 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* BODY */}
        <div className="flex-1 relative">
          {loading ? (
            <div className="absolute inset-0 flex items-center justify-center flex-col gap-4">
              <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
              <p className="font-mono-data text-xs uppercase tracking-widest text-white/50">
                Geolocalizando IPs...
              </p>
            </div>
          ) : valid.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center flex-col gap-3">
              <MapPin className="w-10 h-10 text-white/20" />
              <p className="text-white/50">Sin IPs geolocalizables</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] h-full">
              <div className="relative bg-[#050505]">
                <MapContainer
                  center={center}
                  zoom={valid.length > 1 ? 2 : 4}
                  scrollWheelZoom
                  style={{ height: "100%", width: "100%", background: "#050505" }}
                >
                  <TileLayer
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                    url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                    className="map-tiles-dark"
                  />
                  {valid.map((g) => (
                    <Marker key={g.ip} position={[g.latitude, g.longitude]}>
                      <Popup>
                        <div className="text-xs font-mono" style={{ minWidth: 200 }}>
                          <div className="font-bold text-sm mb-1">{g.ip}</div>
                          <div className="text-gray-600 mb-2">
                            {g.hostnames?.slice(0, 3).join(", ") || ""}
                          </div>
                          <div><b>País:</b> {g.flag ? `${g.flag} ` : ""}{g.country || "—"}</div>
                          <div><b>Ciudad:</b> {g.city || "—"}{g.region ? ` (${g.region})` : ""}</div>
                          <div><b>ISP:</b> {g.isp || "—"}</div>
                          {g.asn && <div><b>ASN:</b> {g.asn}</div>}
                        </div>
                      </Popup>
                    </Marker>
                  ))}
                </MapContainer>
              </div>

              {/* SIDEBAR LIST */}
              <div className="border-l border-white/10 overflow-y-auto">
                <div className="p-4 border-b border-white/10 font-mono-data text-[10px] uppercase tracking-widest text-white/50">
                  IPs detectadas
                </div>
                {valid.map((g) => (
                  <div
                    key={g.ip}
                    data-testid={`geoip-row-${g.ip}`}
                    className="p-4 border-b border-white/5 hover:bg-white/[0.03]"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Server className="w-3.5 h-3.5 text-cyan-400" />
                      <span className="font-mono-data text-sm text-cyan-400">{g.ip}</span>
                      {g.flag && <span className="ml-auto text-lg">{g.flag}</span>}
                    </div>
                    <div className="text-xs text-white/70 space-y-0.5">
                      <div><span className="text-white/40 font-mono-data text-[10px] uppercase tracking-widest">País: </span>{g.country || "—"}</div>
                      <div><span className="text-white/40 font-mono-data text-[10px] uppercase tracking-widest">Ciudad: </span>{g.city || "—"}</div>
                      <div><span className="text-white/40 font-mono-data text-[10px] uppercase tracking-widest">ISP: </span>{g.isp || "—"}</div>
                      {g.hostnames?.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {g.hostnames.slice(0, 4).map((h) => (
                            <span key={h} className="font-mono-data text-[10px] border border-white/10 px-1.5 py-0.5 text-white/60">
                              {h}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                {geoip?.filter((g) => !g.success).length > 0 && (
                  <div className="p-4 text-xs text-white/40">
                    {geoip.filter((g) => !g.success).length} IP(s) no geolocalizables
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
