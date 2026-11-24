# Prototipo de Trazabilidad y Verificación Criptográfica de Integridad para Modelos de IA (`Blockchain + Ed25519`)

**Proyecto marco:** *Criptografía e Inteligencia Artificial*  
**Línea de investigación:** Comunicaciones e Informática en Sistemas de Defensa  
**Alineación:** Objetivo Específico 2 (OE2), Objetivo Específico 4 (OE4) y Año 1 – Semestre 2 (Prototipo Blockchain v0.1)

---

## 1. Problema que resuelve

En sistemas críticos y de ciberdefensa que dependen de modelos de Aprendizaje Automático (`.pt`, `.onnx`, `.pkl`), existen cuatro riesgos operativos principales sobre los artefactos desplegados:

1. **Alteración silenciosa (*Model Tampering*):** la modificación de pocos bytes en los pesos de un modelo puede degradar su precisión o introducir comportamientos anómalos sin alertar al nodo consumidor.
2. **Suplantación de origen:** sin firmas digitales asimétricas, un actor no autorizado podría reemplazar el artefacto por un modelo envenenado.
3. **Ausencia de trazabilidad e historial modificable:** los logs planos o hashes aislados no garantizan orden cronológico ni impiden que un atacante altere el registro histórico junto con el archivo.
4. **Falta de bloqueo automático previo a la inferencia:** es necesario auditar la cadena de custodia y el estado operativo del modelo antes de cargarlo en memoria.

## 2. Solución implementada (v0.1)

El prototipo implementa una **cadena de custodia permisionada** (arquitectura limpia separando `dominio`, `aplicacion` e `infraestructura`):

* **Integridad del artefacto:** cómputo determinístico **SHA-256** del archivo `.pt` entrenado en PyTorch.
* **Autenticidad y no repudio:** firma digital asimétrica **Ed25519** sobre el *payload* canónico JSON de cada bloque.
* **Inmutabilidad encadenada:** cada `BloqueAuditoria` enlaza el `hash_bloque` del bloque anterior (`hash_anterior`) y recalcula su hash incluyendo la firma.
* **Ciclo de vida controlado (Patrón State):** `NO_REGISTRADO` → `REGISTRADO` → `APROBADO` → `REVOCADO` / `COMPROMETIDO`. Solo un modelo en estado `APROBADO` y con hash coincidente queda habilitado para inferencia.

## 3. Estructura del repositorio

```text
├── docs/
│   └── INFORME_AVANCE_OE4_S2.md      # Informe técnico formal listo para elevar
├── scripts/
│   └── ejecutar_experimento.py       # Demostración reproducible de los 4 escenarios
├── src/cripto_ia_integridad/
│   ├── dominio/                      # Entidades, Value Objects, State, Operaciones y Puertos
│   ├── aplicacion/                   # ServicioCustodiaModelos
│   └── infraestructura/              # SHA-256, Ed25519, Repositorio JSON y modelo PyTorch demo
├── tests/
│   └── test_integridad_modelos.py    # Suite de pruebas unitarias y de integración
└── pyproject.toml
```

## 4. Cómo ejecutar

```powershell
# 1. Ejecutar suite de pruebas unitarias y de integración
python -m unittest discover -s tests -v

# 2. Ejecutar el experimento reproducible completo (4 escenarios de ataque y verificación)
python scripts/ejecutar_experimento.py
```
