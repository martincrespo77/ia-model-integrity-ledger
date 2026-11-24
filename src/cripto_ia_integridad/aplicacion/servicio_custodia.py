"""Servicio de aplicación para orquestar la custodia criptográfica de modelos de IA."""

from __future__ import annotations

from cripto_ia_integridad.dominio.bloque import BloqueAuditoria
from cripto_ia_integridad.dominio.cadena import CadenaCustodia, ResultadoVerificacionModelo
from cripto_ia_integridad.dominio.contratos import (
    FirmadorAsimetrico,
    ProveedorTiempo,
    RepositorioCadena,
    ServicioHash,
    VerificadorAsimetrico,
)
from cripto_ia_integridad.dominio.excepciones import IntegridadModeloError
from cripto_ia_integridad.dominio.valores import IdentidadActor, IdModelo, VersionSemantica


class ServicioCustodiaModelos:
    """Orquesta casos de uso entre el repositorio de cadena y el dominio puro."""

    def __init__(
        self,
        *,
        repositorio: RepositorioCadena,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
        reloj: ProveedorTiempo,
    ) -> None:
        self._repositorio = repositorio
        self._servicio_hash = servicio_hash
        self._verificador = verificador
        self._reloj = reloj

    def inicializar_red(
        self,
        *,
        autoridad_inicial: IdentidadActor,
        firmador_inicial: FirmadorAsimetrico,
        actores_adicionales: list[IdentidadActor] | None = None,
    ) -> CadenaCustodia:
        """Crea la red permisionada con su bloque génesis y la persiste."""
        cadena = CadenaCustodia.inicializar_con_genesis(
            autoridad_inicial=autoridad_inicial,
            firmador=firmador_inicial,
            servicio_hash=self._servicio_hash,
            verificador=self._verificador,
            marca_temporal=self._reloj.ahora_utc(),
            actores_adicionales=actores_adicionales,
        )
        self._repositorio.guardar(cadena)
        return cadena

    def registrar_modelo_desde_archivo(
        self,
        *,
        id_modelo: IdModelo,
        version: VersionSemantica,
        ruta_artefacto: str,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        observacion: str = "Registro inicial de artefacto IA.",
    ) -> BloqueAuditoria:
        """Calcula el SHA-256 del artefacto en disco, firma el bloque y persiste."""
        cadena = self._repositorio.cargar()
        hash_artefacto = self._servicio_hash.calcular_archivo(ruta_artefacto)
        bloque = cadena.registrar_modelo(
            id_modelo=id_modelo,
            version=version,
            hash_artefacto=hash_artefacto,
            actor=actor,
            firmador=firmador,
            servicio_hash=self._servicio_hash,
            verificador=self._verificador,
            marca_temporal=self._reloj.ahora_utc(),
            observacion=observacion,
        )
        self._repositorio.guardar(cadena)
        return bloque

    def aprobar_modelo(
        self,
        *,
        id_modelo: IdModelo,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        observacion: str = "Aprobación operativa tras validación.",
    ) -> BloqueAuditoria:
        """Autoriza la versión vigente del modelo para ser utilizada en inferencia."""
        cadena = self._repositorio.cargar()
        bloque = cadena.aprobar_modelo(
            id_modelo=id_modelo,
            actor=actor,
            firmador=firmador,
            servicio_hash=self._servicio_hash,
            verificador=self._verificador,
            marca_temporal=self._reloj.ahora_utc(),
            observacion=observacion,
        )
        self._repositorio.guardar(cadena)
        return bloque

    def revocar_modelo(
        self,
        *,
        id_modelo: IdModelo,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        observacion: str = "Revocación administrativa de versión.",
    ) -> BloqueAuditoria:
        """Retira de servicio un modelo previamente autorizado."""
        cadena = self._repositorio.cargar()
        bloque = cadena.revocar_modelo(
            id_modelo=id_modelo,
            actor=actor,
            firmador=firmador,
            servicio_hash=self._servicio_hash,
            verificador=self._verificador,
            marca_temporal=self._reloj.ahora_utc(),
            observacion=observacion,
        )
        self._repositorio.guardar(cadena)
        return bloque

    def verificar_artefacto_previo_inferencia(
        self,
        *,
        id_modelo: IdModelo,
        ruta_artefacto: str,
        actor_auditor: IdentidadActor | None = None,
        firmador_auditor: FirmadorAsimetrico | None = None,
    ) -> ResultadoVerificacionModelo:
        """Verifica cadena + estado + SHA-256; si hay alteración y se provee auditor, registra el incidente."""
        cadena = self._repositorio.cargar()
        hash_actual = self._servicio_hash.calcular_archivo(ruta_artefacto)
        try:
            return cadena.verificar_para_inferencia(
                id_modelo=id_modelo,
                hash_artefacto_actual=hash_actual,
                servicio_hash=self._servicio_hash,
                verificador=self._verificador,
            )
        except IntegridadModeloError:
            if actor_auditor is not None and firmador_auditor is not None:
                cadena.reportar_compromiso(
                    id_modelo=id_modelo,
                    hash_observado=hash_actual,
                    actor=actor_auditor,
                    firmador=firmador_auditor,
                    servicio_hash=self._servicio_hash,
                    verificador=self._verificador,
                    marca_temporal=self._reloj.ahora_utc(),
                    observacion="Alteración de artefacto detectada en verificación pre-inferencia.",
                )
                self._repositorio.guardar(cadena)
            raise

    def auditar_cadena_completa(self) -> int:
        """Valida criptográficamente todos los bloques almacenados y devuelve su cantidad."""
        cadena = self._repositorio.cargar()
        return cadena.auditar_integridad(
            servicio_hash=self._servicio_hash,
            verificador=self._verificador,
        )
