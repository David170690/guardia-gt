# GuardIA GT

Plataforma de gestión preventiva de riesgos cibernéticos para instituciones públicas y privadas de Guatemala.

## Qué hace hoy

| Módulo | Estado | Origen de los datos |
|---|---|---|
| Autenticación y roles | Operativo | bcrypt + JWT sobre PostgreSQL |
| Diagnóstico de red | Operativo | Escaneo TCP real y lectura de certificados TLS |
| Vulnerabilidades / Activos / Incidentes | Operativo | CRUD sobre la base de datos |
| Cumplimiento | Operativo | Controles cargados en la plataforma |
| Dashboard | Operativo | Agregaciones calculadas sobre los datos |
| Reportes y tendencias | Operativo | Calculados sobre fechas reales de hallazgos |
| Exportación CSV / PDF | Operativo | CSV de inventarios y PDF ejecutivo con datos reales |
| Bitácora de auditoría | Operativo | Se escribe en `audit_logs` |
| Doble factor (MFA) | Operativo | TOTP compatible con Google Authenticator |
| **Informe ejecutivo con IA** | Operativo | Redacción a partir de hallazgos reales (modelo o plantilla) |

Ya no queda ninguna pantalla con datos ficticios. El informe ejecutivo con IA usa un
modelo abierto cuando hay clave configurada, y una plantilla determinista sobre los
hallazgos reales cuando no la hay: en ningún caso se inventan cifras.

## Informe ejecutivo con IA

La pantalla de IA toma los hallazgos reales de una organización diagnosticada y produce
un resumen para dirección más un plan de remediación priorizado.

- **Con modelo** (`AI_API_KEY` definida): un modelo abierto vía OpenRouter (MiMo por
  defecto) redacta la prosa. El prompt le prohíbe añadir cifras o CVEs que no estén en
  los datos.
- **Sin modelo**: una plantilla determinista compone el informe con los mismos hallazgos.

Para activar el modelo, crea una cuenta gratuita en [OpenRouter](https://openrouter.ai),
genera una API key y define `AI_API_KEY` y `AI_MODEL` (el slug exacto del modelo libre).

## Confirmación de CVEs

El escáner reporta *exposiciones* sin afirmar CVEs. Si `CVE_LOOKUP_ENABLED=true`, cuando
un banner revela producto y versión se consulta la API pública del NVD y, si hay
coincidencias reales, se añaden hallazgos de tipo `cve` con identificadores verificados.
Está desactivado por defecto porque el NVD limita las peticiones.

## Qué detecta el diagnóstico

El escáner abre conexiones TCP contra las direcciones indicadas y reporta:

- **Exposición de servicios** — bases de datos, escritorios remotos y paneles alcanzables desde la red.
- **Protocolos en claro** — Telnet, FTP, POP3 e IMAP sin cifrado.
- **Servicios web sin TLS** — HTTP publicado sin equivalente HTTPS.
- **Certificados TLS** — se lee el certificado real del servidor: dominio, emisor y fecha de vencimiento.
- **Divulgación de versión** — banners que revelan el software y su versión.
- **Alcanzabilidad** — activos que no respondieron, indicando el motivo.

El escáner **no afirma CVEs sin evidencia**. Un puerto abierto se reporta como
exposición, no como vulnerabilidad conocida: sin detección de versión no hay forma
de saber si el servicio es vulnerable a un CVE concreto.

### Límites

- Las direcciones privadas (`192.168.x`, `10.x`, `172.16-31.x`), de loopback y link-local
  se rechazan por defecto. Un servidor en internet no puede alcanzarlas, y permitirlo
  convertiría la API en una sonda hacia la red interna del proveedor.
  Para inventarios internos, instala GuardIA dentro de la red del cliente y activa
  `SCAN_ALLOW_PRIVATE_TARGETS=true`.
- Máximo 25 activos por diagnóstico (`SCAN_MAX_ASSETS`).
- Escanea únicamente infraestructura que tengas autorización para evaluar.

## Stack

**Backend** — Python 3.11, FastAPI, SQLAlchemy 2, PostgreSQL 16, JWT (python-jose), bcrypt
**Frontend** — React 18, Vite 5, TypeScript, Tailwind CSS, Recharts, Framer Motion
**Infraestructura** — Docker Compose para desarrollo, Render.com para producción

## Instalación

### Con Docker

```bash
cp .env.example backend/.env
docker compose up -d --build
```

- Frontend: http://localhost:5173
- API: http://localhost:8000
- Documentación: http://localhost:8000/docs

### Sin Docker

```bash
# Backend
cd backend
python -m venv .venv && .venv/Scripts/activate   # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
uvicorn app.main:app --reload --port 8000

# Frontend (en otra terminal)
cd frontend
npm install
npm run dev
```

### Cargar datos de demostración

`POST /seed` está deshabilitado mientras `SEED_TOKEN` esté vacío. Para usarlo:

```bash
# Define SEED_TOKEN en el entorno, luego:
curl -X POST http://localhost:8000/seed -H "X-Seed-Token: tu-token"

# O desde el CLI, sin token:
cd backend && python seed_data.py
```

Usuarios de demostración: `admin@guardia.gt` / `Admin123!` y `analista@guardia.gt` / `Analyst123!`.
**Cámbialas antes de exponer la instancia.**

## Pruebas

```bash
cd backend
pip install -r requirements.txt
pytest
```

La suite cubre el control de acceso de todos los endpoints, la validación de destinos
del escáner, la generación de hallazgos y el aislamiento de datos entre organizaciones.

## Seguridad

- Todos los endpoints de datos exigen un token de acceso. Solo `/api/auth/*` y `/health` son públicos.
- El registro público siempre crea usuarios con rol `viewer`; los roles los asigna un administrador.
- Los roles se aplican en la API: `viewer` es solo lectura, `analyst` puede escribir, `admin` gestiona usuarios.
- Un token de refresco no sirve para consumir la API.
- Doble factor opcional con TOTP; el login exige el código de seis dígitos si está activo.
- Límite de tasa en el login (10/min) y el diagnóstico (6/min) para frenar abuso.
- Las acciones sensibles (inicio de sesión, cambios de usuario, MFA, diagnósticos) quedan en `audit_logs`.

## Estructura

```
guardia-gt/
├── backend/
│   ├── app/
│   │   ├── core/          # config, base de datos, seguridad, dependencias, auditoría
│   │   ├── models/        # modelos SQLAlchemy
│   │   ├── routes/        # endpoints
│   │   ├── schemas/       # esquemas Pydantic
│   │   ├── services/      # escáner de red
│   │   └── seed.py        # datos de demostración
│   ├── tests/             # pytest
│   └── alembic/           # migraciones
├── frontend/src/
│   ├── components/        # Layout, Modal, DataNote, Skeleton, Toast
│   ├── context/           # AuthContext
│   ├── pages/             # 11 páginas
│   ├── services/          # cliente Axios
│   └── types/             # tipos compartidos
├── docker-compose.yml
├── render.yaml
└── .env.example
```

## API

| Método | Endpoint | Acceso |
|---|---|---|
| POST | `/api/auth/register` | Público (crea rol `viewer`) |
| POST | `/api/auth/login` | Público |
| POST | `/api/auth/refresh` | Público |
| GET | `/api/auth/me` | Autenticado |
| GET | `/api/dashboard/` | Autenticado |
| GET/POST/PUT/DELETE | `/api/vulnerabilities/` | Lectura autenticada, escritura `analyst`+ |
| GET/POST/PUT/DELETE | `/api/assets/` | Lectura autenticada, escritura `analyst`+ |
| GET/POST/PUT | `/api/incidents/` | Lectura autenticada, escritura `analyst`+ |
| GET/POST/PUT | `/api/compliance/` | Lectura autenticada, escritura `analyst`+ |
| GET | `/api/reports/`, `/api/reports/trends` | Autenticado |
| GET | `/api/reports/export/{tipo}` (CSV), `/api/reports/pdf` | Autenticado |
| POST | `/api/diagnostic/run` | Autenticado · máx. 6/min |
| GET/POST | `/api/ai/status`, `/api/ai/organizations`, `/api/ai/report` | Autenticado |
| GET/PUT | `/api/settings/*` | Autenticado |
| POST | `/api/settings/mfa/{setup,enable,disable}` | Autenticado |
| GET/POST/PUT/DELETE | `/api/users/` | `admin` |
| POST | `/seed` | Cabecera `X-Seed-Token` |
| GET | `/health` | Público |

## Licencia

Proyecto académico — Universidad Mariano Gálvez de Guatemala
Maestría en Ingeniería en Sistemas de Información
