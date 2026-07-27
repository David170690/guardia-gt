# GuardIA GT

Plataforma Inteligente de Gestión Preventiva de Riesgos Cibernéticos con Inteligencia Artificial

## Descripción

GuardIA GT es una plataforma de ciberseguridad diseñada para instituciones públicas y privadas de Guatemala que permite conocer en minutos el estado de seguridad informática de una organización utilizando Inteligencia Artificial.

## Características Principales

- **Diagnóstico Automático** — Evaluación rápida del estado de seguridad
- **5 Estándares Internacionales** — ISO 27001, NIST CSF 2.0, CIS Controls v8, OWASP Top 10, MITRE ATT&CK
- **IA Predictiva** — Predicción de ataques y priorización de vulnerabilidades
- **SOC Virtual 24/7** — Monitoreo continuo de incidentes
- **Dashboard Ejecutivo** — KPIs en tiempo real
- **Reportes Automáticos** — Generación de informes con IA

## Stack Tecnológico

### Backend
- Python 3.11
- FastAPI
- PostgreSQL 16
- SQLAlchemy + Alembic
- JWT Authentication

### Frontend
- React 18
- Vite
- TypeScript
- Tailwind CSS
- Recharts

### Infraestructura
- Docker + Docker Compose
- Render.com (deploy)
- Nginx (reverse proxy)

## Instalación

### Requisitos Previos
- Docker Desktop
- Python 3.11+
- Node.js 18+

### Pasos

1. Clonar el repositorio
```bash
git clone https://github.com/tu-usuario/guardia-gt.git
cd guardia-gt
```

2. Iniciar servicios
```bash
docker-compose up -d
```

3. Crear usuario administrador
```bash
docker exec -it guardia-backend python -m app.seed_data
```

4. Acceder a la aplicación
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- Documentación API: http://localhost:8000/docs

## Credenciales por Defecto

| Email | Password | Rol |
|-------|----------|-----|
| admin@guardia.gt | Admin123! | admin |
| analista@guardia.gt | Analyst123! | analyst |

## Estructura del Proyecto

```
guardia-gt/
├── backend/
│   ├── app/
│   │   ├── core/          # Configuración, seguridad, DB
│   │   ├── models/        # Modelos SQLAlchemy
│   │   ├── routes/        # Endpoints API
│   │   ├── schemas/       # Schemas Pydantic
│   │   └── services/      # Lógica de negocio
│   ├── alembic/           # Migraciones
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/    # Componentes React
│   │   ├── pages/         # Páginas
│   │   ├── services/      # API services
│   │   └── hooks/         # Custom hooks
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

## API Endpoints

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | /api/auth/register | Registrar usuario |
| POST | /api/auth/login | Iniciar sesión |
| GET | /api/dashboard | Dashboard ejecutivo |
| GET | /api/vulnerabilities | Listar vulnerabilidades |
| GET | /api/compliance | Controles de cumplimiento |
| GET | /api/assets | Inventario de activos |
| GET | /api/incidents | Incidentes de seguridad |

## Licencia

Proyecto académico — Universidad Mariano Gálvez de Guatemala
Programa de Posgrados — Maestría en Ingeniería en Sistemas de Información
