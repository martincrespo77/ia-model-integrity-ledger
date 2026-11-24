"""Agregado raíz: Cadena de custodia permisionada para modelos de IA."""

from __future__ import annotations

from dataclasses import dataclass

from cripto_ia_integridad.dominio.bloque import BloqueAuditoria
from cripto_ia_integridad.dominio.contratos import (
    FirmadorAsimetrico,
    ServicioHash,
    VerificadorAsimetrico,
)
from cripto_ia_integridad.dominio.estados_modelo import (
    EstadoModelo,
    EstadoNoRegistrado,
)
from cripto_ia_integridad.dominio.excepciones import (
    ActorNoAutorizadoError,
    CadenaCorruptaError,
    FirmaInvalidaError,
    IntegridadModeloError,
    ModeloNoRegistradoError,
)
from cripto_ia_integridad.dominio.operaciones import (
    OperacionAprobacionModelo,
    OperacionCompromisoModelo,
    OperacionGenesis,
    OperacionRegistroModelo,
    OperacionRevocacionModelo,
)
from cripto_ia_integridad.dominio.valores import (
    HashSHA256,
    IdentidadActor,
    IdModelo,
    MarcaTemporalUTC,
    VersionSemantica,
)


@dataclass(frozen=True, slots=True)
class ResultadoVerificacionModelo:
    """Resumen inmutable de la verificación previa a inferencia."""

    id_modelo: IdModelo
    version_vigente: VersionSemantica
    estado_codigo: str
    hash_registrado: HashSHA256
    hash_observado: HashSHA256
    total_bloques_auditados: int
    integro: bool


class CadenaCustodia:
    """Blockchain permisionada que custodia la integridad y ciclo de vida de modelos IA."""

    def __init__(
        self,
        bloques: list[BloqueAuditoria],
        actores_autorizados: dict[str, IdentidadActor],
    ) -> None:
        if not bloques:
            raise CadenaCorruptaError("La cadena de custodia requiere al menos el bloque génesis.")
        self._bloques: list[BloqueAuditoria] = list(bloques)
        self._actores_autorizados: dict[str, IdentidadActor] = dict(actores_autorizados)

    @classmethod
    def inicializar_con_genesis(
        cls,
        *,
        autoridad_inicial: IdentidadActor,
        firmador: FirmadorAsimetrico,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
        marca_temporal: MarcaTemporalUTC,
        actores_adicionales: list[IdentidadActor] | None = None,
    ) -> CadenaCustodia:
        """Crea una cadena nueva firmando el bloque génesis (#0)."""
        actores: dict[str, IdentidadActor] = {
            autoridad_inicial.identificador: autoridad_inicial
        }
        for actor in actores_adicionales or []:
            actores[actor.identificador] = actor

        genesis = BloqueAuditoria.crear_firmado(
            indice=0,
            marca_temporal=marca_temporal,
            operacion=OperacionGenesis(),
            id_modelo=IdModelo("sistema.genesis"),
            version_modelo=VersionSemantica("0.0.0"),
            hash_artefacto=HashSHA256.genesis(),
            hash_anterior=HashSHA256.genesis(),
            actor=autoridad_inicial,
            observacion="Bloque génesis de red permisionada Cripto-IA.",
            firmador=firmador,
            servicio_hash=servicio_hash,
        )
        if not genesis.verificar_firma(verificador):
            raise FirmaInvalidaError(
                "La clave privada del firmador inicial no corresponde a la autoridad génesis."
            )
        return cls(bloques=[genesis], actores_autorizados=actores)

    @classmethod
    def reconstruir(
        cls,
        *,
        bloques: list[BloqueAuditoria],
        actores_autorizados: list[IdentidadActor],
    ) -> CadenaCustodia:
        """Rehidrata una cadena desde almacenamiento externo para su posterior auditoría."""
        mapa_actores = {actor.identificador: actor for actor in actores_autorizados}
        return cls(bloques=bloques, actores_autorizados=mapa_actores)

    @property
    def bloques(self) -> tuple[BloqueAuditoria, ...]:
        """Vista inmutable de los bloques de la cadena."""
        return tuple(self._bloques)

    @property
    def actores_autorizados(self) -> tuple[IdentidadActor, ...]:
        """Vista inmutable de los actores habilitados en la red permisionada."""
        return tuple(self._actores_autorizados.values())

    @property
    def ultimo_bloque(self) -> BloqueAuditoria:
        return self._bloques[-1]

    def registrar_actor_autorizado(self, actor: IdentidadActor) -> None:
        """Incorpora una identidad autorizada al consorcio permisionado."""
        self._actores_autorizados[actor.identificador] = actor

    def registrar_modelo(
        self,
        *,
        id_modelo: IdModelo,
        version: VersionSemantica,
        hash_artefacto: HashSHA256,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
        marca_temporal: MarcaTemporalUTC,
        observacion: str = "Registro inicial de artefacto IA.",
    ) -> BloqueAuditoria:
        """Registra un artefacto de IA validando permisos, estado y firma antes de mutar."""
        return self._agregar_bloque_transicion(
            operacion=OperacionRegistroModelo(),
            id_modelo=id_modelo,
            version_modelo=version,
            hash_artefacto=hash_artefacto,
            actor=actor,
            firmador=firmador,
            servicio_hash=servicio_hash,
            verificador=verificador,
            marca_temporal=marca_temporal,
            observacion=observacion,
        )

    def aprobar_modelo(
        self,
        *,
        id_modelo: IdModelo,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
        marca_temporal: MarcaTemporalUTC,
        observacion: str = "Aprobación operativa tras auditoría.",
    ) -> BloqueAuditoria:
        """Autoriza la última versión registrada del modelo para inferencia."""
        ultimo_registro = self._obtener_ultimo_bloque_modelo(id_modelo)
        return self._agregar_bloque_transicion(
            operacion=OperacionAprobacionModelo(),
            id_modelo=id_modelo,
            version_modelo=ultimo_registro.version_modelo,
            hash_artefacto=ultimo_registro.hash_artefacto,
            actor=actor,
            firmador=firmador,
            servicio_hash=servicio_hash,
            verificador=verificador,
            marca_temporal=marca_temporal,
            observacion=observacion,
        )

    def revocar_modelo(
        self,
        *,
        id_modelo: IdModelo,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
        marca_temporal: MarcaTemporalUTC,
        observacion: str = "Revocación de versión operativa.",
    ) -> BloqueAuditoria:
        """Retira de servicio un modelo autorizado."""
        ultimo_registro = self._obtener_ultimo_bloque_modelo(id_modelo)
        return self._agregar_bloque_transicion(
            operacion=OperacionRevocacionModelo(),
            id_modelo=id_modelo,
            version_modelo=ultimo_registro.version_modelo,
            hash_artefacto=ultimo_registro.hash_artefacto,
            actor=actor,
            firmador=firmador,
            servicio_hash=servicio_hash,
            verificador=verificador,
            marca_temporal=marca_temporal,
            observacion=observacion,
        )

    def reportar_compromiso(
        self,
        *,
        id_modelo: IdModelo,
        hash_observado: HashSHA256,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
        marca_temporal: MarcaTemporalUTC,
        observacion: str = "Compromiso detectado durante verificación.",
    ) -> BloqueAuditoria:
        """Asienta evidencia inmutable de alteración del artefacto."""
        ultimo_registro = self._obtener_ultimo_bloque_modelo(id_modelo)
        return self._agregar_bloque_transicion(
            operacion=OperacionCompromisoModelo(),
            id_modelo=id_modelo,
            version_modelo=ultimo_registro.version_modelo,
            hash_artefacto=hash_observado,
            actor=actor,
            firmador=firmador,
            servicio_hash=servicio_hash,
            verificador=verificador,
            marca_temporal=marca_temporal,
            observacion=observacion,
        )

    def auditar_integridad(
        self,
        *,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
    ) -> int:
        """Recorre toda la cadena verificando hashes, enlaces, permisos y firmas."""
        if self._bloques[0].indice != 0 or self._bloques[0].hash_anterior != HashSHA256.genesis():
            raise CadenaCorruptaError("El bloque génesis (#0) tiene índice o enlace previo inválido.")

        for posicion, bloque in enumerate(self._bloques):
            if bloque.indice != posicion:
                raise CadenaCorruptaError(
                    f"Secuencia rota en posición {posicion}: índice encontrado {bloque.indice}."
                )
            if posicion > 0:
                bloque_previo = self._bloques[posicion - 1]
                if bloque.hash_anterior != bloque_previo.hash_bloque:
                    raise CadenaCorruptaError(
                        f"Ruptura de encadenamiento en bloque #{bloque.indice}: "
                        f"hash_anterior={bloque.hash_anterior.valor[:12]}... != "
                        f"bloque #{bloque_previo.indice}={bloque_previo.hash_bloque.valor[:12]}..."
                    )
            hash_recalculado = bloque.calcular_hash_esperado(servicio_hash)
            if hash_recalculado != bloque.hash_bloque:
                raise CadenaCorruptaError(
                    f"Manipulación detectada en bloque #{bloque.indice}: "
                    f"hash almacenado={bloque.hash_bloque.valor[:12]}... != "
                    f"recalculado={hash_recalculado.valor[:12]}..."
                )
            self._validar_autorizacion_y_firma(bloque, verificador)

        return len(self._bloques)

    def estado_de_modelo(self, id_modelo: IdModelo) -> EstadoModelo:
        """Reconstruye el estado actual de un modelo aplicando polimórficamente sus bloques."""
        estado: EstadoModelo = EstadoNoRegistrado()
        for bloque in self._bloques:
            if bloque.id_modelo == id_modelo:
                estado = bloque.operacion.aplicar_a(estado)
        return estado

    def verificar_para_inferencia(
        self,
        *,
        id_modelo: IdModelo,
        hash_artefacto_actual: HashSHA256,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
    ) -> ResultadoVerificacionModelo:
        """Auditoría completa: integridad del ledger, ciclo de vida aprobado y hash exacto."""
        total_auditados = self.auditar_integridad(
            servicio_hash=servicio_hash,
            verificador=verificador,
        )
        estado = self.estado_de_modelo(id_modelo)
        estado.validar_habilitado_para_inferencia()
        ultimo_bloque = self._obtener_ultimo_bloque_modelo(id_modelo)

        if hash_artefacto_actual != ultimo_bloque.hash_artefacto:
            raise IntegridadModeloError(
                f"Artefacto alterado para '{id_modelo.valor}' v{ultimo_bloque.version_modelo.valor}: "
                f"esperado={ultimo_bloque.hash_artefacto.valor[:16]}..., "
                f"observado={hash_artefacto_actual.valor[:16]}..."
            )

        return ResultadoVerificacionModelo(
            id_modelo=id_modelo,
            version_vigente=ultimo_bloque.version_modelo,
            estado_codigo=estado.codigo,
            hash_registrado=ultimo_bloque.hash_artefacto,
            hash_observado=hash_artefacto_actual,
            total_bloques_auditados=total_auditados,
            integro=True,
        )

    def _agregar_bloque_transicion(
        self,
        *,
        operacion,
        id_modelo: IdModelo,
        version_modelo: VersionSemantica,
        hash_artefacto: HashSHA256,
        actor: IdentidadActor,
        firmador: FirmadorAsimetrico,
        servicio_hash: ServicioHash,
        verificador: VerificadorAsimetrico,
        marca_temporal: MarcaTemporalUTC,
        observacion: str,
    ) -> BloqueAuditoria:
        # Validar antes de mutar (INV-04): autorización, transición de estado y firma.
        self._validar_actor_autorizado(actor)
        estado_actual = self.estado_de_modelo(id_modelo)
        _ = operacion.aplicar_a(estado_actual)

        nuevo_bloque = BloqueAuditoria.crear_firmado(
            indice=self.ultimo_bloque.indice + 1,
            marca_temporal=marca_temporal,
            operacion=operacion,
            id_modelo=id_modelo,
            version_modelo=version_modelo,
            hash_artefacto=hash_artefacto,
            hash_anterior=self.ultimo_bloque.hash_bloque,
            actor=actor,
            observacion=observacion,
            firmador=firmador,
            servicio_hash=servicio_hash,
        )
        self._validar_autorizacion_y_firma(nuevo_bloque, verificador)
        self._bloques.append(nuevo_bloque)
        return nuevo_bloque

    def _validar_actor_autorizado(self, actor: IdentidadActor) -> None:
        autorizado = self._actores_autorizados.get(actor.identificador)
        if autorizado is None:
            raise ActorNoAutorizadoError(
                f"El actor '{actor.identificador}' no pertenece a la red permisionada."
            )
        if autorizado.clave_publica != actor.clave_publica:
            raise ActorNoAutorizadoError(
                f"La clave pública presentada para '{actor.identificador}' no coincide con la autorizada."
            )

    def _validar_autorizacion_y_firma(
        self,
        bloque: BloqueAuditoria,
        verificador: VerificadorAsimetrico,
    ) -> None:
        self._validar_actor_autorizado(bloque.actor)
        if not bloque.verificar_firma(verificador):
            raise FirmaInvalidaError(
                f"Firma digital Ed25519 inválida en bloque #{bloque.indice} para actor '{bloque.actor.identificador}'."
            )

    def _obtener_ultimo_bloque_modelo(self, id_modelo: IdModelo) -> BloqueAuditoria:
        for bloque in reversed(self._bloques):
            if bloque.id_modelo == id_modelo:
                return bloque
        raise ModeloNoRegistradoError(f"No existen registros para el modelo '{id_modelo.valor}'.")
