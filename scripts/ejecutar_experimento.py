"""Experimento reproducible (PoC v0.1): Custodia criptográfica de modelos de IA.

Ejecuta 4 escenarios controlados:
  1. Flujo legítimo: entrenamiento PyTorch -> registro SHA-256 + Ed25519 -> aprobación -> inferencia.
  2. Ataque de alteración silenciosa (Model Tampering): modificación de 1 byte en los pesos `.pt`.
  3. Ataque de suplantación (Unauthorized Replacement): firma con clave no autorizada.
  4. Manipulación del historial (Ledger Tampering): alteración manual de `ledger.json`.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cripto_ia_integridad.aplicacion.servicio_custodia import ServicioCustodiaModelos
from cripto_ia_integridad.dominio.excepciones import (
    ActorNoAutorizadoError,
    CadenaCorruptaError,
    FirmaInvalidaError,
    IntegridadModeloError,
)
from cripto_ia_integridad.dominio.valores import IdentidadActor, IdModelo, VersionSemantica
from cripto_ia_integridad.infraestructura.cripto_ed25519 import (
    FirmadorEd25519,
    RelojUTC,
    ServicioHashSHA256,
    VerificadorEd25519,
)
from cripto_ia_integridad.infraestructura.modelo_ia_demo import (
    corromper_un_byte_artefacto,
    ejecutar_inferencia_pt,
    entrenar_y_guardar_modelo_demo,
)
from cripto_ia_integridad.infraestructura.repositorio_json import RepositorioCadenaJSON


def ejecutar_experimento(directorio_trabajo: Path) -> dict[str, object]:
    """Ejecuta todos los escenarios y devuelve métricas verificables."""
    ruta_ledger = directorio_trabajo / "ledger_custodia.json"
    ruta_modelo = directorio_trabajo / "detector_anomalias_red_v1.pt"

    servicio_hash = ServicioHashSHA256()
    verificador = VerificadorEd25519()
    reloj = RelojUTC()
    repositorio = RepositorioCadenaJSON(str(ruta_ledger))
    servicio = ServicioCustodiaModelos(
        repositorio=repositorio,
        servicio_hash=servicio_hash,
        verificador=verificador,
        reloj=reloj,
    )

    # Identidades de la red permisionada
    firmador_autoridad = FirmadorEd25519.generar_nuevo()
    autoridad = IdentidadActor(
        identificador="autoridad-ciberdefensa",
        organizacion="FIE-Ciberdefensa",
        clave_publica=firmador_autoridad.obtener_clave_publica(),
    )

    firmador_investigador = FirmadorEd25519.generar_nuevo()
    investigador = IdentidadActor(
        identificador="nodo-entrenamiento-ia",
        organizacion="Lab-IA-Cripto",
        clave_publica=firmador_investigador.obtener_clave_publica(),
    )

    firmador_atacante = FirmadorEd25519.generar_nuevo()
    atacante = IdentidadActor(
        identificador="actor-externo-no-autorizado",
        organizacion="Desconocida",
        clave_publica=firmador_atacante.obtener_clave_publica(),
    )

    id_modelo = IdModelo("detector-anomalias-red")
    version = VersionSemantica("1.0.0")

    # ------------------------------------------------------------------
    # ESCENARIO 1: Flujo legítimo completo
    # ------------------------------------------------------------------
    resumen_entrenamiento = entrenar_y_guardar_modelo_demo(str(ruta_modelo))

    t0 = time.perf_counter()
    servicio.inicializar_red(
        autoridad_inicial=autoridad,
        firmador_inicial=firmador_autoridad,
        actores_adicionales=[investigador],
    )
    bloque_reg = servicio.registrar_modelo_desde_archivo(
        id_modelo=id_modelo,
        version=version,
        ruta_artefacto=str(ruta_modelo),
        actor=investigador,
        firmador=firmador_investigador,
        observacion="Modelo PyTorch entrenado con semilla=42.",
    )
    bloque_aprob = servicio.aprobar_modelo(
        id_modelo=id_modelo,
        actor=autoridad,
        firmador=firmador_autoridad,
        observacion="Aprobado para inferencia en nodo operativo.",
    )
    t_registro_ms = round((time.perf_counter() - t0) * 1000, 3)

    t1 = time.perf_counter()
    verificacion_ok = servicio.verificar_artefacto_previo_inferencia(
        id_modelo=id_modelo,
        ruta_artefacto=str(ruta_modelo),
    )
    t_verificacion_ms = round((time.perf_counter() - t1) * 1000, 3)

    clase_predicha, probs = ejecutar_inferencia_pt(str(ruta_modelo), [0.82, 0.77, 0.80, 0.86])

    escenario_1 = {
        "nombre": "1. Flujo legítimo (registro + aprobación + inferencia)",
        "resultado": "PERMITIDO",
        "detalle": (
            f"Bloques={verificacion_ok.total_bloques_auditados}, "
            f"Estado={verificacion_ok.estado_codigo}, "
            f"Predicción={clase_predicha} (p={probs})"
        ),
        "tiempo_ms": t_verificacion_ms,
    }

    # ------------------------------------------------------------------
    # ESCENARIO 3 (antes de corromper): Ataque de suplantación / firma no autorizada
    # ------------------------------------------------------------------
    try:
        servicio.registrar_modelo_desde_archivo(
            id_modelo=id_modelo,
            version=VersionSemantica("1.0.1"),
            ruta_artefacto=str(ruta_modelo),
            actor=atacante,
            firmador=firmador_atacante,
            observacion="Intento de reemplazo malicioso.",
        )
        escenario_3 = {
            "nombre": "3a. Actor externo no autorizado",
            "resultado": "FALLO_DE_SEGURIDAD",
            "detalle": "Se permitió registrar sin autorización",
            "tiempo_ms": 0.0,
        }
    except ActorNoAutorizadoError as exc:
        escenario_3 = {
            "nombre": "3a. Actor externo no autorizado",
            "resultado": "BLOQUEADO",
            "detalle": str(exc),
            "tiempo_ms": 0.0,
        }

    # También probamos un actor autorizado cuya identidad se usa con clave privada falsa
    t_s3 = time.perf_counter()
    try:
        servicio.registrar_modelo_desde_archivo(
            id_modelo=id_modelo,
            version=VersionSemantica("1.0.2"),
            ruta_artefacto=str(ruta_modelo),
            actor=investigador,
            firmador=firmador_atacante,
            observacion="Intento de suplantación de identidad con clave ajena.",
        )
        escenario_3b = {
            "nombre": "3b. Suplantación con firma Ed25519 falsa",
            "resultado": "FALLO_DE_SEGURIDAD",
            "detalle": "Se aceptó firma inválida",
            "tiempo_ms": 0.0,
        }
    except FirmaInvalidaError as exc:
        escenario_3b = {
            "nombre": "3b. Suplantación con firma Ed25519 falsa",
            "resultado": "BLOQUEADO",
            "detalle": str(exc),
            "tiempo_ms": round((time.perf_counter() - t_s3) * 1000, 3),
        }

    # ------------------------------------------------------------------
    # ESCENARIO 2: Alteración silenciosa de 1 byte en el artefacto PyTorch
    # ------------------------------------------------------------------
    offset_corrupto = corromper_un_byte_artefacto(str(ruta_modelo))
    t2 = time.perf_counter()
    try:
        servicio.verificar_artefacto_previo_inferencia(
            id_modelo=id_modelo,
            ruta_artefacto=str(ruta_modelo),
            actor_auditor=autoridad,
            firmador_auditor=firmador_autoridad,
        )
        escenario_2 = {
            "nombre": "2. Alteración de 1 byte en pesos .pt",
            "resultado": "FALLO_DE_SEGURIDAD",
            "detalle": "No se detectó la alteración",
            "tiempo_ms": 0.0,
        }
    except IntegridadModeloError as exc:
        t_det_tamper_ms = round((time.perf_counter() - t2) * 1000, 3)
        escenario_2 = {
            "nombre": f"2. Alteración de 1 byte en pesos .pt (byte #{offset_corrupto})",
            "resultado": "BLOQUEADO",
            "detalle": str(exc),
            "tiempo_ms": t_det_tamper_ms,
        }

    # ------------------------------------------------------------------
    # ESCENARIO 4: Manipulación directa del archivo ledger_custodia.json
    # ------------------------------------------------------------------
    ledger_json = json.loads(ruta_ledger.read_text(encoding="utf-8"))
    # Atacante reemplaza el hash registrado en el bloque #1 por un hash falso
    ledger_json["bloques"][1]["hash_artefacto"] = "f" * 64
    ruta_ledger.write_text(json.dumps(ledger_json, indent=2), encoding="utf-8")

    t4 = time.perf_counter()
    try:
        servicio.auditar_cadena_completa()
        escenario_4 = {
            "nombre": "4. Manipulación de historial en ledger.json",
            "resultado": "FALLO_DE_SEGURIDAD",
            "detalle": "No se detectó alteración en el ledger",
            "tiempo_ms": 0.0,
        }
    except CadenaCorruptaError as exc:
        escenario_4 = {
            "nombre": "4. Manipulación de historial en ledger.json",
            "resultado": "BLOQUEADO",
            "detalle": str(exc),
            "tiempo_ms": round((time.perf_counter() - t4) * 1000, 3),
        }

    return {
        "modelo": {
            "id": id_modelo.valor,
            "version": version.valor,
            "tamano_bytes": resumen_entrenamiento.tamano_bytes,
            "precision_entrenamiento": resumen_entrenamiento.precision_entrenamiento,
            "hash_original": bloque_reg.hash_artefacto.valor,
            "hash_bloque_registro": bloque_reg.hash_bloque.valor,
            "hash_bloque_aprobacion": bloque_aprob.hash_bloque.valor,
            "tiempo_inicializacion_y_registro_ms": t_registro_ms,
        },
        "escenarios": [escenario_1, escenario_2, escenario_3, escenario_3b, escenario_4],
    }


def main() -> None:
    consola = Console()
    with tempfile.TemporaryDirectory(prefix="cripto_ia_poc_") as tmp:
        resultados = ejecutar_experimento(Path(tmp))

    modelo_info = resultados["modelo"]
    consola.rule("[bold cyan]PoC v0.1 — Custodia Criptográfica de Modelos IA (Blockchain + Ed25519)")
    consola.print(f"[bold]Modelo PyTorch:[/bold] {modelo_info['id']} v{modelo_info['version']} "
                  f"({modelo_info['tamano_bytes']} bytes, precisión entrenamiento={modelo_info['precision_entrenamiento']})")
    consola.print(f"[bold]SHA-256 original:[/bold] {modelo_info['hash_original']}")
    consola.print(f"[bold]Tiempo registro+aprobación:[/bold] {modelo_info['tiempo_inicializacion_y_registro_ms']} ms\n")

    tabla = Table(title="Resultados Experimentales por Escenario")
    tabla.add_column("Escenario", style="cyan")
    tabla.add_column("Resultado", style="bold")
    tabla.add_column("Tiempo (ms)", justify="right")
    tabla.add_column("Diagnóstico / Evidencia")

    for item in resultados["escenarios"]:
        estilo = "green" if item["resultado"] in ("PERMITIDO", "BLOQUEADO") else "red"
        tabla.add_row(
            item["nombre"],
            f"[{estilo}]{item['resultado']}[/{estilo}]",
            f"{item['tiempo_ms']:.3f}",
            item["detalle"],
        )

    consola.print(tabla)


if __name__ == "__main__":
    main()
