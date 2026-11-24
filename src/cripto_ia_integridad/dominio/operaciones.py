"""Operaciones polimórficas registrables en un bloque de la cadena de custodia."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cripto_ia_integridad.dominio.estados_modelo import EstadoModelo
from cripto_ia_integridad.dominio.excepciones import ValorInvalidoError


class OperacionCustodia(ABC):
    """Contrato polimórfico para los eventos registrados en cada bloque."""

    @property
    @abstractmethod
    def codigo(self) -> str:
        """Identificador canónico de la operación en el registro."""

    @abstractmethod
    def aplicar_a(self, estado_actual: EstadoModelo) -> EstadoModelo:
        """Ejecuta la transición correspondiente sobre el estado del modelo."""


class OperacionGenesis(OperacionCustodia):
    """Evento inicial de arranque de la cadena de custodia."""

    @property
    def codigo(self) -> str:
        return "GENESIS"

    def aplicar_a(self, estado_actual: EstadoModelo) -> EstadoModelo:
        return estado_actual


class OperacionRegistroModelo(OperacionCustodia):
    """Registra el hash inicial o una nueva versión de un artefacto de IA."""

    @property
    def codigo(self) -> str:
        return "REGISTRO_MODELO"

    def aplicar_a(self, estado_actual: EstadoModelo) -> EstadoModelo:
        return estado_actual.registrar()


class OperacionAprobacionModelo(OperacionCustodia):
    """Autoriza un modelo previamente registrado para inferencia operativa."""

    @property
    def codigo(self) -> str:
        return "APROBACION_MODELO"

    def aplicar_a(self, estado_actual: EstadoModelo) -> EstadoModelo:
        return estado_actual.aprobar()


class OperacionRevocacionModelo(OperacionCustodia):
    """Retira un modelo de operación por obsolescencia o política."""

    @property
    def codigo(self) -> str:
        return "REVOCACION_MODELO"

    def aplicar_a(self, estado_actual: EstadoModelo) -> EstadoModelo:
        return estado_actual.revocar()


class OperacionCompromisoModelo(OperacionCustodia):
    """Registra en el ledger que se detectó alteración o compromiso de integridad."""

    @property
    def codigo(self) -> str:
        return "COMPROMISO_DETECTADO"

    def aplicar_a(self, estado_actual: EstadoModelo) -> EstadoModelo:
        return estado_actual.marcar_comprometido()


class FabricaOperacionesCustodia:
    """Reconstruye operaciones de custodia desde su código serializado."""

    _MAPA: dict[str, type[OperacionCustodia]] = {
        "GENESIS": OperacionGenesis,
        "REGISTRO_MODELO": OperacionRegistroModelo,
        "APROBACION_MODELO": OperacionAprobacionModelo,
        "REVOCACION_MODELO": OperacionRevocacionModelo,
        "COMPROMISO_DETECTADO": OperacionCompromisoModelo,
    }

    @classmethod
    def desde_codigo(cls, codigo: str) -> OperacionCustodia:
        tipo = cls._MAPA.get(codigo.strip().upper())
        if tipo is None:
            raise ValorInvalidoError(f"Operación de custodia desconocida: '{codigo}'.")
        return tipo()
