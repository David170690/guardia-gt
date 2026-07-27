# GuardIA GT — Sesión de Desarrollo 27/Julio/2026

## Resumen Ejecutivo

Plataforma de ciberseguridad con IA desplegada y operativa en Render.com.
Stack: **FastAPI** (Python 3.11) + **React/Vite** (TypeScript) + **PostgreSQL** (Render Managed).

---

## 1. Infraestructura Desplegada

| Servicio | URL | Estado |
|---|---|---|
| Frontend | https://guardia-gt-frontend.onrender.com | ✅ LIVE |
| Backend API | https://guardia-gt-backend.onrender.com | ✅ LIVE |
| Health Check | https://guardia-gt-backend.onrender.com/health | ✅ OK |
| Swagger Docs | https://guardia-gt-backend.onrender.com/docs | ✅ OK |
| Base de Datos | PostgreSQL en Render (guardia-gt-db) | ✅ Operativa |
| Repositorio | https://github.com/David170690/guardia-gt | ✅ Sync |

---

## 2. Arquitectura del Sistema

```
guardia-gt/
├── backend/
│   ├── app/
│   │   ├── main.py              # Entry point FastAPI, CORS, routers, seed, create_all
│   │   ├── core/
│   │   │   ├── config.py        # Settings (DATABASE_URL, SECRET_KEY, CORS_ORIGINS)
│   │   │   ├── database.py      # SQLAlchemy engine + SSL Render + SessionLocal
│   │   │   └── security.py      # JWT (access/refresh), bcrypt, password hash
│   │   ├── models/
│   │   │   ├── user.py          # User + UserRole (admin/analyst/viewer)
│   │   │   ├── vulnerability.py # Vulnerability + Severity + VulnStatus
│   │   │   ├── asset.py         # Asset + AssetType + Criticality + Status
│   │   │   ├── incident.py      # Incident + IncidentSeverity + IncidentStatus
│   │   │   ├── compliance.py    # ComplianceControl + Standard + ComplianceStatus
│   │   │   └── audit_log.py     # AuditLog (relación con User)
│   │   ├── routes/
│   │   │   ├── auth.py          # login, register, refresh, /me
│   │   │   ├── dashboard.py     # Dashboard agregado
│   │   │   ├── vulnerabilities.py # CRUD vulnerabilidades + stats
│   │   │   ├── compliance.py    # CRUD cumplimiento + dashboard
│   │   │   ├── assets.py        # CRUD activos + stats
│   │   │   ├── incidents.py     # CRUD incidentes + stats
│   │   │   ├── reports.py       # Reportes + tendencias
│   │   │   ├── users.py         # CRUD usuarios (admin only)
│   │   │   ├── settings.py      # Perfil, contraseña, config sistema
│   │   │   └── diagnostic.py    # Escaneo/diagnóstico para nuevos clientes
│   │   └── schemas/
│   │       ├── auth.py          # UserCreate, UserLogin, UserResponse, Token
│   │       ├── vulnerability.py
│   │       ├── asset.py
│   │       ├── incident.py
│   │       ├── compliance.py
│   │       └── dashboard.py
│   ├── seed_data.py             # Script de seed (ya no se usa, migrado a /seed)
│   ├── requirements.txt         # Dependencias Python
│   └── .python-version          # 3.11
├── frontend/
│   ├── src/
│   │   ├── App.tsx              # Router principal + AuthProvider
│   │   ├── main.tsx             # Entry point React
│   │   ├── context/
│   │   │   └── AuthContext.tsx  # Context global de autenticación
│   │   ├── hooks/
│   │   │   └── useAuth.ts       # Hook legacy (reemplazado por AuthContext)
│   │   ├── services/
│   │   │   └── api.ts           # Axios client + todas las funciones de API
│   │   ├── components/
│   │   │   └── Layout.tsx       # Sidebar + Outlet (navegación)
│   │   └── pages/
│   │       ├── Login.tsx        # Formulario login con branding
│   │       ├── Dashboard.tsx    # Dashboard ejecutivo con métricas
│   │       ├── Vulnerabilities.tsx # Tabla CVEs + filtros por severidad
│   │       ├── Compliance.tsx   # 5 estándares (ISO, NIST, CIS, OWASP, MITRE)
│   │       ├── Assets.tsx       # Inventario TI con CPU/RAM
│   │       ├── Incidents.tsx    # Gestión de incidentes SOC
│   │       ├── AIInsights.tsx   # IA predictiva + métricas
│   │       ├── Reports.tsx      # Gráficas tendencia + reportes PDF
│   │       ├── Diagnostic.tsx   # Nuevo diagnóstico para clientes
│   │       ├── Users.tsx        # CRUD usuarios admin
│   │       └── Settings.tsx     # Perfil, contraseña, sistema
│   ├── vite.config.ts           # Vite config + preview.allowedHosts
│   ├── package.json
│   └── .node-version            # 18
├── render.yaml                  # Config despliegue Render
└── docker-compose.yml           # Para desarrollo local
```

---

## 3. Módulos Implementados

### 3.1 Autenticación y Autorización
- JWT con access token + refresh token
- RBAC: Admin, Analyst, Viewer
- Login / Register / Refresh / /me
- Protección de rutas en frontend (AuthContext)
- Credenciales demo:
  - `admin@guardia.gt` / `Admin123!` (Admin)
  - `analista@guardia.gt` / `Analyst123!` (Analyst)

### 3.2 Dashboard Ejecutivo
- Score de riesgo general (0-100)
- Tarjetas: Vulnerabilidades, Cumplimiento, Activos, Incidentes
- Gráfico de riesgo por categoría (Red, Apps, Endpoint, Cloud, Correo)
- Amenazas activas en tiempo real

### 3.3 Vulnerabilidades
- Tabla completa con CVE, Título, CVSS, Severidad, Estado, Activo
- Filtros: Todas, Crítico, Alto, Medio, Bajo
- Estadísticas por severidad

### 3.4 Cumplimiento Normativo
- 5 estándares evaluados simultáneamente:
  - ISO 27001
  - NIST CSF 2.0
  - CIS Controls v8
  - OWASP Top 10
  - MITRE ATT&CK
- Score por estándar + hallazgos críticos

### 3.5 Gestión de Activos TI
- Inventario con nombre, IP, tipo, SO, criticidad
- Monitoreo CPU/RAM en tiempo real
- Estados: Online, Offline, Mantenimiento
- Filtros por tipo

### 3.6 Gestión de Incidentes (SOC Virtual)
- Timeline de incidentes con severidad
- MTTR (Mean Time to Resolve)
- Estados: Abierto, Investigando, Contenido, Resuelto
- Acciones de respuesta documentadas

### 3.7 IA Predictiva
- Predicción de ataques (patrones 90 días)
- Análisis de riesgos con priorización automática
- Generación automática de reportes
- Métricas: Precisión predicciones, Tiempo respuesta IA

### 3.8 Reportes y Analítica
- Tendencia de riesgo (6 meses)
- Métricas de seguridad (remediados, MTTR, bloqueados, phishing)
- Reportes generados descargables

### 3.9 Nuevo Diagnóstico (para clientes nuevos)
- Formulario: nombre organización, rango IPs, tipo escaneo
- Agregar múltiples activos a escanear
- Ejecuta escaneo y retorna:
  - Activos creados
  - Vulnerabilidades encontradas
  - Incidentes generados
  - Score de cumplimiento
  - Nivel de riesgo
- **Cards clickeables** con detalle expandible:
  - Activos: nombre, IP, tipo, SO, criticidad
  - Vulnerabilidades: CVE, CVSS, severidad, solución
  - Incidentes: severidad, activo, acción de respuesta
  - Cumplimiento: controles por estándar con score

### 3.10 Gestión de Usuarios (Admin)
- Tabla con todos los usuarios
- Crear usuario (nombre, email, contraseña, rol)
- Editar usuario
- Activar/Desactivar
- Eliminar (no permite auto-eliminación)

### 3.11 Configuración
- **Perfil**: editar nombre y email
- **Contraseña**: cambiar contraseña (valida la actual)
- **Sistema**: info de la organización, email alertas, escaneo automático, retención datos, MFA

---

## 4. Credenciales y Acceso

| Campo | Valor |
|---|---|
| URL Frontend | https://guardia-gt-frontend.onrender.com |
| Email Admin | admin@guardia.gt |
| Pass Admin | Admin123! |
| Email Analista | analista@guardia.gt |
| Pass Analista | Analyst123! |

---

## 5. Problemas Resueltos durante la Sesión

### 5.1 Base de datos vacía (no hacía seed)
- **Problema**: La DB existía pero sin datos. Render Shell es de pago.
- **Solución**: Crear endpoint `POST /seed` que crea tablas + datos automáticamente.
- **Commit**: `feat: add /seed endpoint to populate DB via HTTP`

### 5.2 Error 500 en /seed — Tablas no existían
- **Problema**: El endpoint intentaba insertar sin crear tablas.
- **Solución**: Agregar `Base.metadata.create_all(bind=engine)` en startup + dentro del endpoint.
- **Commit**: `fix: create tables before seeding + on startup`

### 5.3 Error bcrypt — password cannot be longer than 72 bytes
- **Problema**: Incompatibilidad entre `passlib==1.7.4` y `bcrypt>=4.1`.
- **Solución**: Fijar `bcrypt==4.0.1` en requirements.txt.
- **Commit**: `fix: pin bcrypt==4.0.1 to fix passlib compatibility`

### 5.4 Vite bloquea host de Render
- **Problema**: `Blocked request. This host is not allowed.`
- **Solución**: Agregar `preview: { allowedHosts: true }` en vite.config.ts.
- **Commit**: `fix: allow all hosts in vite preview for Render`

### 5.5 Login no redirige al Dashboard
- **Problema**: Cada uso de `useAuth()` creaba un estado nuevo con `isAuthenticated: false`.
- **Solución**: Crear `AuthContext.tsx` con Provider para compartir estado global.
- **Commit**: `fix: use AuthContext to share auth state across components`

### 5.6 Conflicto de import `settings`
- **Problema**: `from app.routes import settings` sobreescribía `from app.core.config settings`.
- **Solución**: Renombrar a `from app.routes import settings as settings_router`.
- **Commit**: `fix: rename settings import to avoid conflict, improve asset validation`

### 5.7 Backend no desplegaba (commit anterior al fix)
- **Problema**: Render usaba commit anterior al fix.
- **Solución**: Manual Deploy desde el dashboard de Render.

---

## 6. API Endpoints

### Auth
- `POST /api/auth/register` — Registrar usuario
- `POST /api/auth/login` — Login (devuelve tokens)
- `POST /api/auth/refresh` — Refrescar access token
- `GET /api/auth/me` — Usuario actual

### Dashboard
- `GET /api/dashboard/` — Métricas agregadas

### Vulnerabilidades
- `GET /api/vulnerabilities/` — Listar (filtro: severity, status)
- `GET /api/vulnerabilities/stats` — Estadísticas
- `POST /api/vulnerabilities/` — Crear
- `PUT /api/vulnerabilities/{id}` — Actualizar
- `DELETE /api/vulnerabilities/{id}` — Eliminar

### Cumplimiento
- `GET /api/compliance/` — Listar (filtro: standard)
- `GET /api/compliance/dashboard` — Dashboard de cumplimiento
- `POST /api/compliance/` — Crear
- `PUT /api/compliance/{id}` — Actualizar

### Activos
- `GET /api/assets/` — Listar (filtro: asset_type, status)
- `GET /api/assets/stats` — Estadísticas
- `POST /api/assets/` — Crear
- `PUT /api/assets/{id}` — Actualizar
- `DELETE /api/assets/{id}` — Eliminar

### Incidentes
- `GET /api/incidents/` — Listar (filtro: severity, status)
- `GET /api/incidents/stats` — Estadísticas
- `POST /api/incidents/` — Crear
- `PUT /api/incidents/{id}` — Actualizar

### Reportes
- `GET /api/reports/` — Listar reportes
- `GET /api/reports/trends` — Tendencias 6 meses

### Usuarios (Admin)
- `GET /api/users/` — Listar
- `POST /api/users/` — Crear
- `PUT /api/users/{id}` — Actualizar
- `DELETE /api/users/{id}` — Eliminar
- `PATCH /api/users/{id}/toggle-active` — Activar/Desactivar

### Configuración
- `GET /api/settings/profile` — Ver perfil
- `PUT /api/settings/profile` — Actualizar perfil
- `PUT /api/settings/password` — Cambiar contraseña
- `GET /api/settings/system` — Config del sistema

### Diagnóstico
- `POST /api/diagnostic/run` — Ejecutar escaneo para nuevo cliente

### Setup
- `POST /seed` — Poblar base de datos (solo la primera vez)
- `GET /health` — Health check

---

## 7. Schema de Base de Datos

### Tabla: users
| Campo | Tipo | Notas |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| email | VARCHAR(255) | Unique, indexed |
| full_name | VARCHAR(255) | |
| hashed_password | VARCHAR(255) | bcrypt |
| role | ENUM | admin/analyst/viewer |
| is_active | BOOLEAN | Default true |
| mfa_enabled | BOOLEAN | Default false |
| mfa_secret | VARCHAR(32) | Nullable |
| created_at | DATETIME | Server default |
| updated_at | DATETIME | On update |

### Tabla: vulnerabilities
| Campo | Tipo | Notas |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| cve_id | VARCHAR(20) | Unique, indexed |
| title | VARCHAR(500) | |
| description | TEXT | |
| cvss_score | FLOAT | 0.0 - 10.0 |
| severity | ENUM | critical/high/medium/low/info |
| status | ENUM | open/in_progress/remediated/accepted/false_positive |
| asset_id | INTEGER FK | → assets.id |
| affected_component | VARCHAR(255) | |
| solution | TEXT | |

### Tabla: assets
| Campo | Tipo | Notas |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| name | VARCHAR(255) | |
| asset_type | ENUM | server/endpoint/network/web_app/database/cloud/other |
| ip_address | VARCHAR(45) | IPv4 o IPv6 |
| operating_system | VARCHAR(100) | |
| criticality | ENUM | critical/high/medium/low |
| status | ENUM | online/offline/maintenance/decommissioned |
| cpu_usage | FLOAT | 0-100 |
| ram_usage | FLOAT | 0-100 |

### Tabla: incidents
| Campo | Tipo | Notas |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| title | VARCHAR(500) | |
| description | TEXT | |
| severity | ENUM | critical/high/medium/low |
| status | ENUM | open/investigating/contained/resolved/closed |
| source_ip | VARCHAR(45) | |
| affected_asset | VARCHAR(255) | |
| response_action | TEXT | |
| assigned_to | INTEGER FK | → users.id |

### Tabla: compliance_controls
| Campo | Tipo | Notas |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| standard | ENUM | iso_27001/nist_csf/cis_v8/owasp_top10/mitre_attack |
| control_id | VARCHAR(50) | |
| control_name | VARCHAR(500) | |
| status | ENUM | compliant/partial/non_compliant/not_applicable |
| score | FLOAT | 0-100 |
| findings | TEXT | |

### Tabla: audit_logs
| Campo | Tipo | Notas |
|---|---|---|
| id | INTEGER PK | Auto-increment |
| user_id | INTEGER FK | → users.id |
| action | VARCHAR(100) | |
| resource | VARCHAR(255) | |
| details | TEXT | |
| ip_address | VARCHAR(45) | |

---

## 8. Variables de Entorno (Render)

| Variable | Valor (Backend) |
|---|---|
| DATABASE_URL | Internal Database URL de Render PostgreSQL |
| SECRET_KEY | Generada automáticamente |
| CORS_ORIGINS | https://guardia-gt-frontend.onrender.com |
| PYTHON_VERSION | 3.11 |

| Variable | Valor (Frontend) |
|---|---|
| VITE_API_URL | https://guardia-gt-backend.onrender.com |
| NODE_VERSION | 18 |

---

## 9. Commits de la Sesión

```
a377f98 feat: add /seed endpoint to populate DB via HTTP
5fd9b48 fix: create tables before seeding + on startup
816f2d9 fix: pin bcrypt==4.0.1 to fix passlib compatibility
5345707 fix: allow all hosts in vite preview for Render
a7972d7 fix: use AuthContext to share auth state across components
81ab7bf feat: add users CRUD, diagnostic scan, and settings API routes
d0b6c65 feat: add Users, Diagnostic, and Settings pages
a5df697 fix: rename settings import to avoid conflict, improve asset validation
356e06e feat: diagnostic cards are now clickable with detailed expandable views
```

---

## 10. Pendiente / Próximos Pasos

### Integración con Herramientas Reales de Escaneo
- [ ] **Nessus / OpenVAS** — Escaneo de vulnerabilidades real
- [ ] **Nmap** — Descubrimiento de red y puertos
- [ ] **OSSEC / Wazuh** — Detección de intrusiones
- [ ] **Qualys** — Gestión de vulnerabilidades en la nube
- [ ] **Shodan** — Búsqueda de activos expuestos
- [ ] **Have I Been Pwned API** — Verificación de brechas

### Funcionalidades Adicionales
- [ ] Exportar reportes a PDF real
- [ ] Notificaciones por email
- [ ] Scheduler de escaneos automáticos
- [ ] Dashboard de tendencias con datos históricos reales
- [ ] Integración con SIEM
- [ ] MFA con TOTP (Google Authenticator)
- [ ] Rate limiting en endpoints públicos
- [ ] Logging estructurado + auditoría

### Optimización
- [ ] Paginación en tablas grandes
- [ ] Búsqueda global
- [ ] Cache de métricas del dashboard
- [ ] Lazy loading de páginas
- [ ] PWA (Progressive Web App)

---

## 11. Costos Render (Free Tier)

| Servicio | Plan | Costo Mensual |
|---|---|---|
| Frontend (Static Site) | Free | $0 |
| Backend (Web Service) | Free | $0 |
| PostgreSQL | Free (90 días) | $0* |
| **Total** | | **$0** |

*La DB gratis se elimina después de 90 días de inactividad. Para producción, migrar a plan Starter ($7/mes).

---

## 12. Comandos Útiles

```bash
# Desarrollo local
cd backend && uvicorn app.main:app --reload --port 8000
cd frontend && npm run dev

# Despliegue (auto por push a main)
git add -A && git commit -m "mensaje" && git push origin main

# Seed de datos (desde Swagger)
POST https://guardia-gt-backend.onrender.com/seed

# Health check
curl https://guardia-gt-backend.onrender.com/health
```

---

*Documento generado el 27 de Julio de 2026 — GuardIA GT v1.0.0*
