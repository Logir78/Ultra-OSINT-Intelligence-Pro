# Cómo contribuir

¡Gracias por tu interés en NOCTUA.osint! 🦉

## Flujo de trabajo

1. Haz un fork y crea una rama descriptiva: `git checkout -b fix/nombre-corto`.
2. Levanta el entorno de desarrollo (ver [`README.md`](README.md)).
3. Haz tus cambios con tests cuando aplique.
4. Asegúrate de que pasa todo:
   ```bash
   make lint     # ruff + black --check + mypy
   make test     # pytest
   ```
5. Abre un Pull Request describiendo el qué y el porqué.

## Estilo de código

- **Python:** formateo con `black`, linting con `ruff`, tipos con `mypy`.
  La configuración vive en `backend/pyproject.toml`.
- **JavaScript/React:** ESLint (config en `frontend`). Componentes funcionales
  y hooks; evita añadir más lógica a los archivos ya gigantes — extrae subcomponentes.
- **Commits:** mensajes claros en imperativo. Se recomienda
  [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`…).

## Tests

- Backend: añade tests en `backend/tests/`. Nómbralos por dominio funcional
  (`test_scans.py`, `test_auth.py`), no por número de iteración.
- Frontend: se recomienda Vitest + Testing Library (aún por introducir).

## Reportar bugs / pedir features

Abre un issue con pasos de reproducción claros o una descripción del caso de uso.
Para temas de **seguridad**, sigue [`SECURITY.md`](SECURITY.md) (no los publiques).
