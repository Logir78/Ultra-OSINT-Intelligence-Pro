# Política de seguridad

## Reportar una vulnerabilidad

Si encuentras un problema de seguridad, **no abras un issue público**. Escribe en privado al mantenedor del repositorio con:

- Descripción del problema y su impacto.
- Pasos para reproducirlo.
- Versión / commit afectado.

Intentaremos responder en un plazo razonable y publicar un fix coordinado.

## Consideraciones al desplegar NOCTUA

NOCTUA realiza peticiones de red del lado del servidor hacia dominios que indica
el usuario. Antes de exponerlo a Internet:

1. **CORS** — Define `CORS_ORIGINS` con una allowlist explícita. Nunca combines
   `allow_credentials=True` con `allow_origins="*"`.
2. **SSRF** — Mantén `SSRF_GUARD=1` para impedir que el escáner apunte a
   `localhost`, rangos privados (`10/8`, `172.16/12`, `192.168/16`), link-local
   o el endpoint de metadatos del cloud (`169.254.169.254`). Ver `backend/security.py`.
3. **Rate limiting** — Pon la API detrás de un límite de peticiones (p. ej.
   `slowapi` o el proxy/CDN) para evitar abuso del escáner.
4. **HTTPS** — Termina TLS en un reverse proxy y fuerza HTTPS.
5. **Secretos** — Nunca comitees `.env`. Usa un gestor de secretos en producción.
6. **Acceso** — Usa `AUTHORIZED_EMAILS` para el modo de acceso privado mientras
   el proyecto no sea público.

## Alcance de uso

Esta herramienta es para investigación de seguridad **autorizada**. El uso contra
sistemas de terceros sin permiso puede ser ilegal en tu jurisdicción.
