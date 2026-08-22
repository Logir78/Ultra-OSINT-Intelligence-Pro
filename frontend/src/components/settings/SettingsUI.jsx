/* Small presentational helpers for the Settings page.
 * Extracted verbatim from Settings.jsx (Fase 3).
 */
import { useState } from "react";
import { Loader2, CheckCircle2, XCircle, Eye, EyeOff } from "lucide-react";

export function TestBadge({ result, testing }) {
  if (testing) return <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />;
  if (!result) return null;
  if (result.ok) return (
    <span className="inline-flex items-center gap-1.5 text-green-400 font-mono-data text-[10px] uppercase tracking-widest">
      <CheckCircle2 className="w-4 h-4" /> OK
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1.5 text-red-400 font-mono-data text-[10px] uppercase tracking-widest max-w-[280px] truncate" title={result.detail}>
      <XCircle className="w-4 h-4 flex-shrink-0" /> {result.detail?.slice(0, 42)}
    </span>
  );
}

export function KeyInput({ value, onChange, placeholder, testId, disabled }) {
  const [reveal, setReveal] = useState(false);
  return (
    <div className={`flex items-center border border-white/[0.08] bg-black ${disabled ? "opacity-50" : ""}`}>
      <input
        type={reveal ? "text" : "password"}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        data-testid={testId}
        autoComplete="off"
        disabled={disabled}
        className="flex-1 bg-transparent px-4 py-2.5 font-mono-data text-sm placeholder:text-white/25 focus:outline-none disabled:cursor-not-allowed"
      />
      <button type="button" onClick={() => setReveal((v) => !v)} className="px-3 text-white/40 hover:text-cyan-400" tabIndex={-1} disabled={disabled}>
        {reveal ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
      </button>
    </div>
  );
}
