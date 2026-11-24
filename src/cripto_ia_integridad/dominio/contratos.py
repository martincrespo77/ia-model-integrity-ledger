"""Contratos (puertos) abstractos entre el dominio y la infraestructura."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cripto_ia_integridad.dominio.cadena import CadenaCustodia
    from cripto_ia_integridad.dominio.valores import (
        ClavePublicaPEM,
        FirmaDigital,
        HashSHA256,
        MarcaTemporalUTC,
    )


class ServicioHash(Protocol):
    """Puerto para cómputo determinístico de hashes SHA-256."""

    def calcular_bytes(self, contenido: bytes) -> HashSHA256:
        """Calcula el hash SHA-256 de una secuencia de bytes en memoria."""

    def calcular_archivo(self, ruta_archivo: str) -> HashSHA256:
        """Calcula el hash SHA-256 de un artefacto almacenado en disco."""


class FirmadorAsimetrico(Protocol):
    """Puerto para firmar payloads canónicos mediante criptografía asimétrica."""

    def firmar(self, payload: bytes) -> FirmaDigital:
        """Genera una firma digital verificable sobre `payload`."""

    def obtener_clave_publica(self) -> ClavePublicaPEM:
        """Expone la clave pública asociada al firmador."""


class VerificadorAsimetrico(Protocol):
    """Puerto para validar firmas digitales sin acceso a claves privadas."""

    def verificar(
        self,
        payload: bytes,
        firma: FirmaDigital,
        clave_publica: ClavePublicaPEM,
    ) -> bool:
        """Retorna True si y solo si la firma es criptográficamente válida."""


class ProveedorTiempo(Protocol):
    """Puerto para inyección determinística de tiempo UTC."""

    def ahora_utc(self) -> MarcaTemporalUTC:
        """Devuelve la marca temporal actual en UTC."""


class RepositorioCadena(Protocol):
    """Puerto de persistencia para cargar y guardar la cadena de custodia."""

    def guardar(self, cadena: CadenaCustodia) -> None:
        """Persiste el estado completo de la cadena de custodia."""

    def cargar(self) -> CadenaCustodia:
        """Recupera una cadena previamente persistida."""

    def existe(self) -> bool:
        """Indica si ya existe una cadena almacenada."""
