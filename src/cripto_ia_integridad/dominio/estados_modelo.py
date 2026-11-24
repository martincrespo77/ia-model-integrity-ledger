"""Patrón State para el ciclo de vida de un modelo de IA bajo custodia."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cripto_ia_integridad.dominio.excepciones import (
    IntegridadModeloError,
    ModeloNoRegistradoError,
    TransicionInvalidaError,
)


class EstadoModelo(ABC):
    """Contrato abstracto del ciclo de vida operativo de un modelo de IA."""

    @property
    @abstractmethod
    def codigo(self) -> str:
        """Código inmutable para serialización y auditoría."""

    @abstractmethod
    def registrar(self) -> EstadoModelo:
        """Transición al registrar un artefacto o una nueva versión."""

    @abstractmethod
    def aprobar(self) -> EstadoModelo:
        """Transición al aprobar el modelo para inferencia operativa."""

    @abstractmethod
    def revocar(self) -> EstadoModelo:
        """Transición al retirar de servicio un modelo autorizado."""

    @abstractmethod
    def marcar_comprometido(self) -> EstadoModelo:
        """Transición al detectar alteración o pérdida de integridad."""

    @abstractmethod
    def validar_habilitado_para_inferencia(self) -> None:
        """Verifica si el modelo puede cargarse para ejecutar inferencia."""


class EstadoNoRegistrado(EstadoModelo):
    """Estado inicial antes de que exista un bloque de registro para el modelo."""

    @property
    def codigo(self) -> str:
        return "NO_REGISTRADO"

    def registrar(self) -> EstadoModelo:
        return EstadoRegistrado()

    def aprobar(self) -> EstadoModelo:
        raise ModeloNoRegistradoError("No se puede aprobar un modelo que aún no fue registrado.")

    def revocar(self) -> EstadoModelo:
        raise ModeloNoRegistradoError("No se puede revocar un modelo que aún no fue registrado.")

    def marcar_comprometido(self) -> EstadoModelo:
        raise ModeloNoRegistradoError("No se puede comprometer un modelo no registrado.")

    def validar_habilitado_para_inferencia(self) -> None:
        raise ModeloNoRegistradoError("El modelo no posee registro criptográfico en la cadena.")


class EstadoRegistrado(EstadoModelo):
    """Modelo registrado con hash y firma, pendiente de aprobación operativa."""

    @property
    def codigo(self) -> str:
        return "REGISTRADO"

    def registrar(self) -> EstadoModelo:
        return EstadoRegistrado()

    def aprobar(self) -> EstadoModelo:
        return EstadoAprobado()

    def revocar(self) -> EstadoModelo:
        return EstadoRevocado()

    def marcar_comprometido(self) -> EstadoModelo:
        return EstadoComprometido()

    def validar_habilitado_para_inferencia(self) -> None:
        raise TransicionInvalidaError(
            "El modelo está REGISTRADO pero aún no fue APROBADO para inferencia operativa."
        )


class EstadoAprobado(EstadoModelo):
    """Modelo verificado y autorizado para uso en sistemas críticos."""

    @property
    def codigo(self) -> str:
        return "APROBADO"

    def registrar(self) -> EstadoModelo:
        return EstadoRegistrado()

    def aprobar(self) -> EstadoModelo:
        raise TransicionInvalidaError("El modelo ya se encuentra en estado APROBADO.")

    def revocar(self) -> EstadoModelo:
        return EstadoRevocado()

    def marcar_comprometido(self) -> EstadoModelo:
        return EstadoComprometido()

    def validar_habilitado_para_inferencia(self) -> None:
        return None


class EstadoRevocado(EstadoModelo):
    """Modelo retirado administrativamente de circulación."""

    @property
    def codigo(self) -> str:
        return "REVOCADO"

    def registrar(self) -> EstadoModelo:
        return EstadoRegistrado()

    def aprobar(self) -> EstadoModelo:
        raise TransicionInvalidaError("Un modelo REVOCADO no puede volver a aprobarse sin nuevo registro.")

    def revocar(self) -> EstadoModelo:
        raise TransicionInvalidaError("El modelo ya fue REVOCADO.")

    def marcar_comprometido(self) -> EstadoModelo:
        return EstadoComprometido()

    def validar_habilitado_para_inferencia(self) -> None:
        raise TransicionInvalidaError("Inferencia bloqueada: el modelo fue REVOCADO.")


class EstadoComprometido(EstadoModelo):
    """Estado terminal de seguridad ante alteración comprobada del artefacto."""

    @property
    def codigo(self) -> str:
        return "COMPROMETIDO"

    def registrar(self) -> EstadoModelo:
        raise TransicionInvalidaError(
            "El identificador de modelo está marcado como COMPROMETIDO; requiere nuevo identificador tras auditoría."
        )

    def aprobar(self) -> EstadoModelo:
        raise TransicionInvalidaError("Prohibido aprobar un modelo marcado como COMPROMETIDO.")

    def revocar(self) -> EstadoModelo:
        raise TransicionInvalidaError("Un modelo COMPROMETIDO permanece bloqueado y no cambia a REVOCADO.")

    def marcar_comprometido(self) -> EstadoModelo:
        return self

    def validar_habilitado_para_inferencia(self) -> None:
        raise IntegridadModeloError(
            "Inferencia bloqueada por seguridad: el modelo fue marcado como COMPROMETIDO."
        )


class FabricaEstadosModelo:
    """Fábrica para reconstruir estados desde su código persistido."""

    _MAPA: dict[str, type[EstadoModelo]] = {
        "NO_REGISTRADO": EstadoNoRegistrado,
        "REGISTRADO": EstadoRegistrado,
        "APROBADO": EstadoAprobado,
        "REVOCADO": EstadoRevocado,
        "COMPROMETIDO": EstadoComprometido,
    }

    @classmethod
    def desde_codigo(cls, codigo: str) -> EstadoModelo:
        tipo = cls._MAPA.get(codigo.strip().upper())
        if tipo is None:
            raise TransicionInvalidaError(f"Código de estado de modelo desconocido: '{codigo}'.")
        return tipo()
