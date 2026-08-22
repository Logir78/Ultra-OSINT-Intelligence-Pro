import { ExternalLink, Key } from "lucide-react";

export default function IntegrationEmpty({ provider, keyUrl, freeTier, description }) {
  return (
    <div
      data-testid={`integration-empty-${(provider || "").toLowerCase()}`}
      className="border border-dashed border-white/15 bg-white/[0.02] p-6 rounded-none"
    >
      <div className="flex items-start gap-3 mb-3">
        <Key className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
        <div>
          <div className="font-mono-data text-[10px] uppercase tracking-[0.3em] text-yellow-400 mb-1">
            Integración pendiente
          </div>
          <h4 className="font-heading text-base font-bold">{provider} no configurado</h4>
        </div>
      </div>
      <p className="text-sm text-white/60 mb-3 pl-7">
        {description}{" "}
        {freeTier && (
          <span className="text-white/40">
            Tier gratuito disponible: <span className="text-white/70">{freeTier}</span>.
          </span>
        )}
      </p>
      <div className="pl-7">
        <a
          href={keyUrl}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 border border-cyan-400/40 text-cyan-400 px-3 py-1.5 hover:bg-cyan-400 hover:text-black transition-colors"
        >
          <span className="font-mono-data text-[10px] uppercase tracking-widest">Obtener API key</span>
          <ExternalLink className="w-3 h-3" />
        </a>
        <span className="ml-3 font-mono-data text-[10px] uppercase tracking-widest text-white/40">
          Pégala en backend/.env y reinicia
        </span>
      </div>
    </div>
  );
}
