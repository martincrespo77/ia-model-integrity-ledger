"""Entidad inmutable que representa un bloque en la cadena de custodia de IA."""

from __future__ import annotations

import json
from dataclasses import dataclass

from cripto_ia_integridad.dominio.contratos import (
    FirmadorAsimetrico,
    ServicioHash,
    VerificadorAsimetrico,
)
from cripto_ia_integridad.dominio.excepciones import ValorInvalidoError
from cripto_ia_integridad.dominio.operaciones import OperacionCustodia
from cripto_ia_integridad.dominio.valores import (
    FirmaDigital,
    HashSHA256,
    IdentidadActor,
    IdModelo,
    MarcaTemporalUTC,
    VersionSemantica,
)


@dataclass(frozen=True, slots=True)
class BloqueAuditoria:
    """Bloque firmado e inmutable de trazabilidad para un artefacto de IA."""

    indice: int
    marca_temporal: MarcaTemporalUTC
    operacion: OperacionCustodia
    id_modelo: IdModelo
    version_modelo: VersionSemantica
    hash_artefacto: HashSHA256
    hash_anterior: HashSHA256
    actor: IdentidadActor
    observacion: str
    firma: FirmaDigital
    hash_bloque: HashSHA256

    def __post_init__(self) -> None:
        if self.indice < 0:
            raise ValorInvalidoError(f"El índice del bloque no puede ser negativo: {self.indice}.")
        if len(self.observacion) > 500:
            raise ValorInvalidoError("La observación del bloque excede los 500 caracteres.")

    @classmethod
    def crear_firmado(
        cls,
        *,
        indice: int,
        marca_temporal: MarcaTemporalUTC,
        operacion: OperacionCustodia,
        id_modelo: IdModelo,
        version_modelo: VersionSemantica,
        hash_artefacto: HashSHA256,
        hash_anterior: HashSHA256,
        actor: IdentidadActor,
        observacion: str,
        firmador: FirmadorAsimetrico,
        servicio_hash: ServicioHash,
    ) -> BloqueAuditoria:
        """Construye un bloque válido calculando firma canónica y hash del bloque."""
        payload_firma = cls._construir_payload_firma(
            indice=indice,
            marca_temporal=marca_temporal,
            operacion=operacion,
            id_modelo=id_modelo,
            version_modelo=version_modelo,
            hash_artefacto=hash_artefacto,
            hash_anterior=hash_anterior,
            actor=actor,
            observacion=observacion,
        )
        firma = firmador.firmar(payload_firma)
        hash_bloque = servicio_hash.calcular_bytes(
            cls._construir_payload_bloque(payload_firma, firma)
        )
        return cls(
            indice=indice,
            marca_temporal=marca_temporal,
            operacion=operacion,
            id_modelo=id_modelo,
            version_modelo=version_modelo,
            hash_artefacto=hash_artefacto,
            hash_anterior=hash_anterior,
            actor=actor,
            observacion=observacion,
            firma=firma,
            hash_bloque=hash_bloque,
        )

    def payload_para_firma(self) -> bytes:
        """Serialización determinística del contenido firmado por el actor."""
        return self._construir_payload_firma(
            indice=self.indice,
            marca_temporal=self.marca_temporal,
            operacion=self.operacion,
            id_modelo=self.id_modelo,
            version_modelo=self.version_modelo,
            hash_artefacto=self.hash_artefacto,
            hash_anterior=self.hash_anterior,
            actor=self.actor,
            observacion=self.observacion,
        )

    def calcular_hash_esperado(self, servicio_hash: ServicioHash) -> HashSHA256:
        """Recalcula el hash SHA-256 esperado a partir de los campos actuales."""
        payload_bloque = self._construir_payload_bloque(self.payload_para_firma(), self.firma)
        return servicio_hash.calcular_bytes(payload_bloque)

    def verificar_firma(self, verificador: VerificadorAsimetrico) -> bool:
        """Verifica criptográficamente la firma contra la clave pública del actor."""
        return verificador.verificar(
            payload=self.payload_para_firma(),
            firma=self.firma,
            clave_publica=self.actor.clave_publica,
        )

    @classmethod
    def _construir_payload_firma(
        cls,
        *,
        indice: int,
        marca_temporal: MarcaTemporalUTC,
        operacion: OperacionCustodia,
        id_modelo: IdModelo,
        version_modelo: VersionSemantica,
        hash_artefacto: HashSHA256,
        hash_anterior: HashSHA256,
        actor: IdentidadActor,
        observacion: str,
    ) -> bytes:
        estructura = {
            "indice": indice,
            "marca_temporal": marca_temporal.iso_utc,
            "operacion": operacion.codigo,
            "id_modelo": id_modelo.valor,
            "version_modelo": version_modelo.valor,
            "hash_artefacto": hash_artefacto.valor,
            "hash_anterior": hash_anterior.valor,
            "actor_id": actor.identificador,
            "actor_organizacion": actor.organizacion,
            "actor_clave_publica": actor.clave_publica.contenido_pem,
            "observacion": observacion,
        }
        return json.dumps(estructura, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def _construir_payload_bloque(cls, payload_firma: bytes, firma: FirmaDigital) -> bytes:
        return payload_firma + b"|SIG|" + firma.hex_firma.encode("ascii")
