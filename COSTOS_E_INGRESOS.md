# GuardIA GT — Documento de Costos e Ingresos Proyectados

**Plataforma de Ciberseguridad con IA para Guatemala y Centroamérica**
Versión: 1.0.0 | Fecha: 27 de Julio de 2026

---

## 1. Resumen Ejecutivo

GuardIA GT es una plataforma SaaS de gestión preventiva de riesgos cibernéticos con inteligencia artificial, diseñada para instituciones guatemaltecas y centroamericanas. Este documento presenta los costos operativos estimados y un modelo de ingresos proyectado para los primeros 3 años de operación.

**Inversión inicial estimada:** $0 - $150/mes (fase MVP)
**Punto de equilibrio:** 5-10 clientes en plan básico
**Potencial de ingreso anual (Año 3):** $50,000 - $120,000 USD

---

## 2. Análisis de Costos de Infraestructura

### 2.1 Hosting y Cloud (Render.com)

| Componente | Plan Actual (Gratuito) | Plan Starter | Plan Producción |
|---|---|---|---|
| Frontend (Static Site) | $0/mes | $0/mes | $0/mes |
| Backend (Web Service) | $0/mes | $7/mes (Starter) | $25/mes (Standard) |
| PostgreSQL Database | $0/mes (90 días) | $6/mes (Basic-256mb) | $19/mes (Basic-1gb) |
| Dominio personalizado | $0 | $0.25/mes | $0.25/mes |
| **Total infraestructura** | **$0/mes** | **$13.25/mes** | **$44.25/mes** |

**Notas:**
- Plan gratuito Render: DB se elimina después de 90 días de inactividad
- Plan Starter: Suficiente para 1-10 clientes, ~100 activos escaneados
- Plan Producción: Para 10-50 clientes, alta disponibilidad

### 2.2 Servicios de IA (OpenAI API)

| Modelo | Uso en GuardIA GT | Costo por 1M tokens | Costo mensual estimado |
|---|---|---|---|
| GPT-4.1 Mini | Análisis de vulnerabilidades, generación de reportes | $0.40 input / $1.60 output | $15-30/mes |
| GPT-4.1 Nano | Clasificación de severidad, routing | $0.10 input / $0.40 output | $5-10/mes |
| text-embedding-3-small | Búsqueda semántica de CVEs | $0.02/1M tokens | $1-3/mes |
| **Total IA** | | | **$21-43/mes** |

**Estimación de uso por cliente:**
- 500 peticiones IA/mes (análisis + reportes)
- ~2,000 tokens promedio por petición
- 50 clientes = 25,000 peticiones/mes = ~50M tokens/mes

### 2.3 Herramientas de Escaneo (Integración Futura)

| Herramienta | Licencia | Costo Mensual |
|---|---|---|
| OpenVAS (open source) | GNU GPL | $0 |
| Nmap (open source) | GNU GPL | $0 |
| Nessus Essentials | Gratis (hasta 16 IPs) | $0 |
| Nessus Professional | Comercial | $299/mes |
| Wazuh (open source) | GNU GPL | $0 |
| Shodan API | Comercial | $49/mes (Small) |

**Recomendación para MVP:** OpenVAS + Nmap (gratuitos)
**Para producción:** Nessus Professional + Shodan ($348/mes)

### 2.4 Otros Costos

| Concepto | Costo Mensual |
|---|---|
| Certificado SSL (Let's Encrypt) | $0 (gratuito) |
| Email transaccional (SendGrid) | $0 (plan gratis: 100/día) |
| Monitoreo (UptimeRobot) | $0 (plan gratis) |
| Backups automáticos (Render) | Incluido en plan pago |
| **Total otros** | **$0/mes** |

---

## 3. Resumen de Costos Operativos Mensuales

### Escenario 1: MVP / Prototipo (0-5 clientes)

| Categoría | Costo Mensual |
|---|---|
| Infraestructura (Render Free) | $0 |
| IA (OpenAI - uso mínimo) | $10 |
| Escaneo (OpenVAS + Nmap) | $0 |
| Dominio | $0.25 |
| **Total** | **$10.25/mes** |

### Escenario 2: Fase de Crecimiento (5-25 clientes)

| Categoría | Costo Mensual |
|---|---|
| Infraestructura (Render Starter) | $13.25 |
| IA (OpenAI - uso moderado) | $30 |
| Escaneo (OpenVAS + Nmap) | $0 |
| Email (SendGrid Free) | $0 |
| Dominio + SSL | $0.25 |
| **Total** | **$43.50/mes** |

### Escenario 3: Producción (25-100 clientes)

| Categoría | Costo Mensual |
|---|---|
| Infraestructura (Render Standard) | $44.25 |
| IA (OpenAI - uso alto) | $80 |
| Escaneo (Nessus Pro + Shodan) | $348 |
| Email (SendGrid Essentials) | $20 |
| Soporte técnico (freelance) | $200 |
| Dominio + SSL | $0.25 |
| **Total** | **$692.50/mes** |

### Escenario 4: Escalamiento (100-500 clientes)

| Categoría | Costo Mensual |
|---|---|
| Infraestructura (AWS/GCP) | $500-1,500 |
| IA (OpenAI - uso masivo) | $300-500 |
| Herramientas de escaneo (enterprise) | $500-1,000 |
| Equipo técnico (2 personas) | $2,000-4,000 |
| Marketing digital | $500-1,000 |
| Legal / Contabilidad | $300 |
| **Total** | **$4,100-8,300/mes** |

---

## 4. Modelo de Ingresos

### 4.1 Estructura de Precios Sugerida

Basado en el mercado de ciberseguridad en Guatemala y Latinoamérica:

| Plan | Precio Mensual | Precio Anual (20% desc.) | Target |
|---|---|---|---|
| **Básico** | $49/mes | $470/año | PyMEs (1-25 activos) |
| **Profesional** | $149/mes | $1,430/año | Empresas medianas (26-100 activos) |
| **Empresarial** | $399/mes | $3,830/año | Grandes empresas (101-500 activos) |
| **Institucional** | $799/mes | $7,670/año | Gobierno / Bancos (500+ activos) |

### 4.2 Comparativa con Competencia Regional

| Plataforma | Precio/Mes | Modelo | GuardIA GT vs Competencia |
|---|---|---|---|
| Sophos MDR (BITSO GT) | $12-15/endpoint/mes | Por endpoint | GuardIA GT: $2-6/activo/mes (50% más barato) |
| ESET PROTECT Complete | $8-12/endpoint/mes | Por endpoint | GuardIA GT: Incluye IA + cumplimiento |
| ResGuard LATAM | $250-599/mes | Por plataforma | GuardIA GT: Más completo, precio similar |
| MDR Providers (promedio) | $8-20/endpoint/mes | Por endpoint | GuardIA GT: Solución integral |
| SOC Propio | $8,000-15,000/mes | Equipo + herramientas | GuardIA GT: 95% más barato |

**Ventaja competitiva de GuardIA GT:**
- Solución todo-en-uno (vulnerabilidades + cumplimiento + IA)
- Precio fijo por plataforma (no por endpoint)
- Enfocado en regulaciones guatemaltecas
- IA predictiva incluida
- Interfaz en español

### 4.3 Fuentes de Ingreso Adicionales

| Fuente | Descripción | Ingreso Estimado |
|---|---|---|
| **Consultoría de implementación** | Setup inicial + capacitación | $500-2,000/cliente (único) |
| **Reportes personalizados** | Análisis avanzados bajo demanda | $100-500/reporte |
| **Integraciones API** | Conectar con SIEM/CRM del cliente | $200-1,000/integración |
| **Capacitación certificada** | Cursos de ciberseguridad | $50-200/persona |
| **Soporte premium** | SLA 24/7 + tiempo de respuesta garantizado | $100-300/mes extra |
| **White-label** | Plataforma para MSPs | $2,000-5,000/mes |

---

## 5. Proyecciones de Ingresos (3 Años)

### Año 1: Fase de Lanzamiento

| Trimestre | Clientes | Ingreso Mensual | Ingreso Trimestral |
|---|---|---|---|
| Q1 | 3 | $147 | $441 |
| Q2 | 8 | $392 | $1,176 |
| Q3 | 15 | $735 | $2,205 |
| Q4 | 25 | $1,225 | $3,675 |
| **Total Año 1** | | | **$7,497** |

**Supuestos:**
- 70% Plan Básico ($49), 25% Profesional ($149), 5% Empresarial ($399)
- Adquisición de 2-3 clientes/mes orgánico
- Sin inversión en marketing pagado

### Año 2: Fase de Crecimiento

| Trimestre | Clientes | Ingreso Mensual | Ingreso Trimestral |
|---|---|---|---|
| Q1 | 40 | $1,960 | $5,880 |
| Q2 | 65 | $3,185 | $9,555 |
| Q3 | 90 | $4,410 | $13,230 |
| Q4 | 120 | $5,880 | $17,640 |
| **Total Año 2** | | | **$46,305** |

**Supuestos:**
- 60% Básico, 30% Profesional, 10% Empresarial/Institucional
- Inversión en marketing: $500/mes
- 2 consultorías de implementación/mes ($1,000 c/u)

### Año 3: Fase de Escalamiento

| Trimestre | Clientes | Ingreso Mensual | Ingreso Trimestral |
|---|---|---|---|
| Q1 | 160 | $7,840 | $23,520 |
| Q2 | 220 | $10,780 | $32,340 |
| Q3 | 300 | $14,700 | $44,100 |
| Q4 | 400 | $19,600 | $58,800 |
| **Total Año 3** | | | **$158,760** |

**Supuestos:**
- 50% Básico, 30% Profesional, 15% Empresarial, 5% Institucional
- Ingreso por consultoría: $3,000/mes
- Ingreso por reportes custom: $1,000/mes

---

## 6. Análisis de Rentabilidad

### Estado de Resultados Proyectado (3 Años)

| Concepto | Año 1 | Año 2 | Año 3 |
|---|---|---|---|
| **Ingresos por suscripciones** | $7,497 | $46,305 | $158,760 |
| **Ingresos por servicios** | $2,000 | $18,000 | $48,000 |
| **Ingresos totales** | **$9,497** | **$64,305** | **$206,760** |
| | | | |
| **Costos de infraestructura** | ($522) | ($2,400) | ($12,000) |
| **Costos de IA (OpenAI)** | ($360) | ($2,400) | ($6,000) |
| **Costos de herramientas** | ($0) | ($4,200) | ($12,000) |
| **Costos de personal** | ($0) | ($12,000) | ($48,000) |
| **Marketing** | ($0) | ($6,000) | ($12,000) |
| **Operativos (legal, contab.)** | ($1,200) | ($3,600) | ($6,000) |
| **Costos totales** | **($2,082)** | **($30,600)** | **($96,000)** |
| | | | |
| **Utilidad Bruta** | **$7,415** | **$33,705** | **$110,760** |
| **Margen Bruto** | **78%** | **52%** | **54%** |
| | | | |
| **Utilidad Neta (antes de impuestos)** | **$7,415** | **$33,705** | **$110,760** |

### Punto de Equilibrio

| Escenario | Clientes Necesarios | Ingreso Mensual |
|---|---|---|
| Costos mínimos ($10/mes) | 1 cliente | $49/mes |
| Costos medios ($44/mes) | 1 cliente | $49/mes |
| Costos de producción ($693/mes) | 5 clientes | $245/mes |
| Con 1 empleado ($2,693/mes) | 20 clientes | $980/mes |

---

## 7. Estrategia de Pricing por Mercado

### Guatemala (Mercado Primario)

| Segmento | Tamaño Mercado | Precio Sugerido | Clientes Potenciales |
|---|---|---|---|
| Pirámide empresarial (500 empresas) | $49-149/mes | 50-100 |
| Sector Bancario (16 bancos) | $399-799/mes | 5-10 |
| Sector Gobierno (ministerios) | $799/mes | 10-15 |
| Universidades (85+) | $149-399/mes | 10-20 |
| PyMEs (10,000+) | $49/mes | 100-500 |

### Centroamérica (Expansión)

| País | Precio Ajustado | Mercado Objetivo |
|---|---|---|
| El Salvador | $49-399/mes | Banco central + empresas tech |
| Honduras | $39-299/mes | Sector bananero + textil |
| Costa Rica | $59-499/mes | Sector turismo + tech |
| Panamá | $69-599/mes | Sector financiero |

---

## 8. Análisis de ROI para el Cliente

### Caso: Empresa Guatemalteca (50 empleados, 30 activos)

**Costo sin GuardIA GT:**
| Concepción | Costo Mensual |
|---|---|
| SOC propio (3 analistas) | $4,500 |
| Herramientas SIEM | $800 |
| Auditoría anual (dividido/mes) | $500 |
| Incidentes no detectados (estimado) | $2,000 |
| **Total** | **$7,800/mes** |

**Costo con GuardIA GT:**
| Concepción | Costo Mensual |
|---|---|
| Plan Profesional | $149 |
| Implementación (amortizada 12 meses) | $83 |
| **Total** | **$232/mes** |

**Ahorro:** $7,568/mes (**97% de reducción**)
**ROI:** 3,262% anual

---

## 9. Factores de Riesgo

| Riesgo | Probabilidad | Impacto | Mitigación |
|---|---|---|---|
| Adopción lenta del mercado | Alta | Medio | Pilotos gratuitos, demos |
| Competencia de Sophos/ESET | Media | Alto | Diferenciación con IA + precio |
| Dependencia de OpenAI | Baja | Medio | Modelos open source (Llama) |
| Regulación de datos | Media | Alto | Cumplimiento LGPD-GT |
| Costos de infraestructura | Baja | Bajo | Escalar gradualmente |
| Rotación de clientes | Media | Alto | Fidelización + valor demostrado |

---

## 10. Recomendaciones

### Para la Tesis (Fase Actual)
1. **Mantener en Render Free** durante la presentación ($0 costos)
2. **Enfocar el pitch** en el ahorro vs SOC propio (97% reducción)
3. **Demostrar datos reales** con integración a OpenVAS/Nmap
4. **Documentar la arquitectura** como ventaja técnica

### Para la Producción (Post-Tesis)
1. **Migrar a Render Starter** ($13.25/mes) cuando haya 3+ clientes
2. **Integrar OpenVAS** como primer escáner gratuito
3. **Crear plan gratuito limitado** (5 activos, 1 usuario) para adquisición
4. **Establecer alianzas** con BITSO, G&K, Intecap para distribución
5. **Obtener certificación** en seguridad informática (ISO 27001 propio)

### Para el Escalamiento (12-24 meses)
1. **Migrar a AWS/GCP** para alta disponibilidad
2. **Contratar equipo de ventas** (2 personas)
3. **Expandir a El Salvador y Costa Rica**
4. **Desarrollar módulo de cumplimiento fiscal** (SAT, SEGEFOR)
5. **Obtener inversión seed** ($50,000-100,000)

---

## 11. Conclusión

GuardIA GT tiene un modelo de negocio **altamente rentable** con costos operativos bajos ($10-700/mes según escala) y un mercado addressable de $5-15 millones anuales solo en Guatemala.

**Cifras clave:**
- **Costo MVP:** $10/mes
- **Primer cliente rentable:** 1 cliente a $49/mes
- **Ingreso proyectado Año 3:** $206,760
- **Margen bruto esperado:** 52-78%
- **ROI para clientes:** 3,000%+

La plataforma está posicionada como la **primera solución de ciberseguridad con IA** enfocada en el mercado guatemalteco, con ventaja significativa en precio y funcionalidad vs competidores internacionales.

---

*Documento preparado para la Maestría en Gerencia de la Tecnología — Universidad Mariano Gálvez de Guatemala*
*Julio 2026*
