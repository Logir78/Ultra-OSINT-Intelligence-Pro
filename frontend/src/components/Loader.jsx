export default function Loader({ label = "Cargando..." }) {
  return (
    <div data-testid="loader" className="min-h-screen flex items-center justify-center bg-[#050505]">
      <div className="flex flex-col items-center gap-4">
        <div className="w-16 h-16 border-2 border-white/10 border-t-cyan-400 rounded-full animate-spin" />
        <p className="font-mono-data text-xs uppercase tracking-[0.3em] text-white/50">{label}</p>
      </div>
    </div>
  );
}
