# Informe de Avance Técnico — Proyecto "Criptografía e Inteligencia Artificial"

**Subproyecto / Contribución:** Prototipo v0.1 de Trazabilidad y Verificación Criptográfica de Integridad para Modelos de Inteligencia Artificial mediante Registro Inmutable (Blockchain Permisionada + Ed25519)  
**Línea de Investigación:** Comunicaciones e Informática en Sistemas de Defensa  
**Área Temática:** Inteligencia Artificial, Criptología y Criptografía  
**Ubicación en el Plan de Trabajo:** Año 1 – Semestre 2 (Exploración experimental inicial)  
**Objetivos Específicos Asociados:** **OE2** (Evaluar la capacidad de la criptografía para proteger modelos y datos de IA) y **OE4** (Examinar el uso de tecnologías Blockchain en aplicaciones de IA — *Prototipo Blockchain versión 0.1*)  
**Fecha:** 24 de noviembre de 2026  

---

## 1. Resumen Ejecutivo

El presente informe documenta el análisis de problemáticas, el diseño arquitectónico, la implementación funcional y la validación experimental de un **prototipo verificable (v0.1)** orientado a proteger la **integridad, autenticidad y trazabilidad** de modelos de Inteligencia Artificial (IA) mediante una cadena de bloques permisionada combinada con resúmenes criptográficos **SHA-256** y firmas digitales asimétricas **Ed25519**.

El desarrollo da respuesta directa al requerimiento metodológico del **Enfoque Experimental (Sección 4.1.4 – Pruebas de Concepto PoC)** y cubre los entregables de **Año 1 – Semestre 2** (*Prototipo Blockchain versión 0.1* y evidencia cuantitativa en entorno controlado), utilizando un modelo neuronal real entrenado en PyTorch (`.pt`) orientado a la detección de anomalías de tráfico de red en escenarios de Ciberdefensa.

---

## 2. Problemas y Desafíos Técnicos Identificados

En entornos críticos y sistemas de defensa que incorporan modelos de aprendizaje automático, la protección del artefacto entrenado (archivo de pesos y parámetros) presenta cuatro vulnerabilidades principales:

1. **Alteración silenciosa de pesos (*Model Tampering*):** La modificación de un único byte en el archivo serializado de una red neuronal (por falla de almacenamiento, interceptación en tránsito o ataque deliberado) puede alterar las predicciones o introducir puertas traseras (*backdoors*) sin generar errores de sintaxis al cargar el modelo.
2. **Suplantación de origen y reemplazo no autorizado (*Model Spoofing / Poisoning*):** Un hash aislado sin firma asimétrica no permite demostrar qué autoridad entrenó, auditó o aprobó el modelo antes de su despliegue en un nodo remoto.
3. **Vulnerabilidad de registros históricos planos:** Almacenar metadatos o hashes en archivos de log convencionales permite que un atacante con acceso de escritura modifique tanto el modelo como el registro histórico sin dejar rastro verificable.
4. **Ausencia de control bloqueante previo a la inferencia:** Los sistemas consumidores suelen cargar archivos `.pt` o `.pkl` directamente sin ejecutar una auditoría previa que verifique simultáneamente la validez de toda la cadena de custodia, el estado administrativo vigente del modelo y el hash exacto del artefacto en disco.

---

## 3. Diseño e Implementación del Prototipo (v0.1)

Para resolver estas cuatro problemáticas se diseñó una arquitectura modular en **Python 3.11** organizada en tres capas desacopladas (`dominio`, `aplicacion` e `infraestructura`):

### 3.1 Primitivas Criptográficas y Estructura del Bloque

* **Integridad del artefacto (`SHA-256`):** Cada versión del modelo se identifica mediante su resumen criptográfico SHA-256 calculado en bloques binarios determinísticos sobre el archivo `.pt`.
* **Autenticidad y no repudio (`Ed25519`):** Cada actor autorizado (ej. `nodo-entrenamiento-ia`, `autoridad-ciberdefensa`) posee un par de claves asimétricas Ed25519 (claves públicas serializadas en PEM). Cada bloque firma un *payload* JSON canónico (`sort_keys=True`, separadores compactos).
* **Encadenamiento inmutable (`BloqueAuditoria`):** Cada bloque almacena:
  * `indice`, `marca_temporal` (UTC ISO-8601), `operacion`, `id_modelo`, `version_modelo`, `hash_artefacto`, `hash_anterior`, `actor`, `observacion`, `firma` y `hash_bloque`.
  * El `hash_bloque` se calcula sobre el *payload* canónico concatenado con la firma digital (`|SIG|`), de modo que alterar cualquier metadato o firma invalida el hash del bloque y rompe todos los bloques posteriores.

### 3.2 Red Permisionada y Máquina de Estados (Patrón *State*)

En coherencia con escenarios de Ciberdefensa (OE4: análisis de redes permisionadas), `CadenaCustodia` mantiene un registro explícito de identidades y claves públicas autorizadas, y modela el ciclo de vida de cada modelo mediante estados polimórficos:

* `NO_REGISTRADO` $\rightarrow$ `REGISTRADO` (al registrar hash y firma del laboratorio)
* `REGISTRADO` $\rightarrow$ `APROBADO` (autorización de la autoridad de ciberdefensa; único estado que habilita la inferencia)
* `APROBADO` $\rightarrow$ `REVOCADO` (retiro administrativo de servicio)
* `REGISTRADO / APROBADO` $\rightarrow$ `COMPROMETIDO` (estado terminal de bloqueo ante alteración detectada)

### 3.3 Modelo de IA Demostrativo (PyTorch)

Se implementó el clasificador neuronal `DetectorAnomaliasRed` (arquitectura MLP `4 -> 16 -> 8 -> 2` en PyTorch) entrenado de manera reproducible (`semilla=42`, 120 épocas sobre telemetría sintética de red normal vs. anómala) y serializado en formato `.pt` (`4.269 bytes`, precisión de entrenamiento `1.0`).

---

## 4. Metodología Experimental y Resultados Obtenidos

Se ejecutaron **7 pruebas automatizadas** (`unittest`) y un **experimento reproducible** (`scripts/ejecutar_experimento.py`) evaluando un flujo operativo normal y cuatro escenarios de ataque controlado.

### 4.1 Resultados de la Suite de Pruebas Automatizadas

* **Comando ejecutado:** `python -m unittest discover -s tests -v`
* **Resultado:** **7/7 pruebas aprobadas (`OK`) en `8.532 s`**, cubriendo validación de *Value Objects*, transiciones ilegales de la máquina de estados y los cuatro escenarios de custodia criptográfica.

### 4.2 Métricas del Experimento Controlado (PoC v0.1)

* **Artefacto evaluado:** `detector-anomalias-red v1.0.0` (`4.269 bytes`)
* **SHA-256 original:** `693e19dd822eb65011ef545e544b4074ae134f466400b97f9102144cd2f2730b`
* **Tiempo de inicialización génesis + registro + aprobación (3 bloques):** `27.741 ms`

| Escenario Evaluado | Resultado | Tiempo (ms) | Evidencia / Comportamiento Observado |
| :--- | :---: | :---: | :--- |
| **1. Flujo legítimo** (registro + aprobación + verificación + inferencia PyTorch) | **PERMITIDO** | `10.361` | Cadena auditada (`3` bloques), estado `APROBADO`, hash coincidente; inferencia habilitada (clase predicha `1`, `p=[0.0, 1.0]`). |
| **2. Alteración silenciosa de 1 byte** en pesos `.pt` (*byte `#4237`*) | **BLOQUEADO** | `10.404` | Lanza `IntegridadModeloError` (esperado `693e19dd822eb...` vs. observado `c010c2bab03b...`), impide cargar el modelo y asienta bloque de compromiso. |
| **3a. Actor externo no autorizado** intenta registrar versión `1.0.1` | **BLOQUEADO** | `0.000` | Lanza `ActorNoAutorizadoError` antes de mutar la cadena; el ledger permanece intacto. |
| **3b. Suplantación de identidad** con firma Ed25519 ajena | **BLOQUEADO** | `0.660` | Lanza `FirmaInvalidaError` al verificar la firma sobre el bloque `#3`; operación rechazada. |
| **4. Manipulación directa del historial** en `ledger_custodia.json` | **BLOQUEADO** | `8.598` | La auditoría detecta divergencia exacta en el bloque `#1` (`7f6032f382d... != cc3ef51c4f...`) lanzando `CadenaCorruptaError`. |

---

## 5. Análisis y Conclusiones

1. **Efectividad frente a ataques de integridad y suplantación:** La combinación de **SHA-256 + Ed25519 + encadenamiento de bloques** demostró capacidad de detección determinística (`100%` en los casos de prueba) ante alteraciones mínimas de un único byte en pesos neuronales, intentos de firma con claves ajenas y manipulación retrospectiva del archivo de historial.
2. **Sobrecarga computacional despreciable:** El costo de verificación previa a la inferencia (`~10.4 ms` sobre 3 bloques y un modelo liviano) resulta viable para controles previos al arranque o carga de modelos en nodos de ciberdefensa sin penalizar la latencia de inferencia posterior.
3. **Aporte al marco metodológico del proyecto:** Se verifica experimentalmente la segunda proposición de la hipótesis (la criptografía fortalece la integridad y auditabilidad de los sistemas de IA), dejando una base modular y extensible hacia la versión `1.0` prevista para el **Semestre 3**.

---

## 6. Limitaciones Actuales (v0.1) y Próximos Pasos hacia Semestre 3

* **Almacenamiento local centralizado:** En esta versión `0.1`, la cadena reside en un archivo JSON local (`RepositorioCadenaJSON`). Para la **versión 1.0 (S3)** se recomienda replicar el ledger entre múltiples nodos validadores con consenso simple (ej. Raft/PBFT o firma multi-autoridad $M$-de-$N$).
* **Gestión de claves privadas:** Las claves Ed25519 experimentales se gestionan en memoria/PEM local; en entorno productivo deben resguardarse en HSM o almacenes cifrados.
* **Transición post-cuántica (OE5):** El diseño desacoplado mediante los puertos `FirmadorAsimetrico` y `VerificadorAsimetrico` permite sustituir `Ed25519` por esquemas post-cuánticos estandarizados por el NIST (ej. ML-DSA / Dilithium) sin modificar la lógica de dominio.
