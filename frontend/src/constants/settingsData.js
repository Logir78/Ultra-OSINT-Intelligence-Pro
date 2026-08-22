/* Static option data for the Settings page. Extracted from Settings.jsx (Fase 3). */

export const PROVIDERS = [
  { id: "shodan",    label: "Shodan",       url: "https://account.shodan.io/",              hint: "100 créditos/mes gratis" },
  { id: "abuseipdb", label: "AbuseIPDB",    url: "https://www.abuseipdb.com/account/api",   hint: "1000 checks/día gratis" },
  { id: "hibp",      label: "Have I Been Pwned", url: "https://haveibeenpwned.com/API/Key", hint: "$3.95/mes" },
  { id: "rapidapi",  label: "BreachDirectory (RapidAPI)", url: "https://rapidapi.com/rohan-patra/api/breachdirectory", hint: "Tier gratis" },
];

export const AI_PROVIDERS = [
  { id: "emergent",   label: "Emergent (por defecto)",  info: "Claude Sonnet 4.6 · Universal Key con crédito incluido" },
  { id: "openai",     label: "OpenAI · GPT-5.4",         info: "Tu propia key de platform.openai.com" },
  { id: "anthropic",  label: "Anthropic · Claude Sonnet 4.6", info: "Tu propia key de console.anthropic.com — usa el tier configurado abajo" },
  { id: "gemini",     label: "Google · Gemini 3.1 Pro",  info: "Tu propia key de aistudio.google.com" },
  { id: "ollama",     label: "Ollama · Local/Self-hosted", info: "Tu instancia Ollama expuesta públicamente (ngrok, cloudflared, servidor)" },
];

export const AI_MODES = [
  { id: "precision",     label: "Modo Precisión (Estricto)",  temp: "0.1", desc: "Informes técnicos ceñidos a datos crudos, sin suposiciones. Ideal para reportes ejecutivos." },
  { id: "investigative", label: "Modo Investigativo (Creativo)", temp: "0.85", desc: "IA busca patrones sutiles, relaciones y posibles vectores de ataque. Ideal para red-team." },
];
