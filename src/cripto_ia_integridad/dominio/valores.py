"""Value Objects inmutables y validados en construcción."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from cripto_ia_integridad.dominio.excepciones import ValorInvalidoError

_RE_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RE_HEX_FIRMA = re.compile(r"^[0-9a-f]{128}$")
_RE_ID_MODELO = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_RE_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$")


@dataclass(frozen=True, slots=True)
class HashSHA256:
    """Resumen criptográfico SHA-256 normalizado en minúsculas (64 hex chars)."""

    valor: str

    def __post_init__(self) -> None:
        normalizado = self.valor.strip().lower()
        if not _RE_HEX_SHA256.match(normalizado):
            raise ValorInvalidoError(
                f"Hash SHA-256 inválido: se esperaban 64 caracteres hexadecimales, recibido '{self.valor}'."
            )
        object.__setattr__(self, "valor", normalizado)

    @classmethod
    def genesis(cls) -> HashSHA256:
        """Hash nulo determinístico utilizado como enlace previo del bloque génesis."""
        return cls("0" * 64)

    def __str__(self) -> str:
        return self.valor


@dataclass(frozen=True, slots=True)
class FirmaDigital:
    """Firma digital Ed25519 representada en hexadecimal (64 bytes = 128 hex chars)."""

    hex_firma: str

    def __post_init__(self) -> None:
        normalizado = self.hex_firma.strip().lower()
        if not _RE_HEX_FIRMA.match(normalizado):
            raise ValorInvalidoError(
                "Firma digital inválida: se esperaba firma Ed25519 de 128 caracteres hexadecimales."
            )
        object.__setattr__(self, "hex_firma", normalizado)

    @classmethod
    def desde_bytes(cls, raw: bytes) -> FirmaDigital:
        if len(raw) != 64:
            raise ValorInvalidoError(
                f"Longitud de firma Ed25519 inválida: {len(raw)} bytes (esperados 64)."
            )
        return cls(raw.hex())

    def a_bytes(self) -> bytes:
        return bytes.fromhex(self.hex_firma)


@dataclass(frozen=True, slots=True)
class ClavePublicaPEM:
    """Clave pública serializada en formato PEM para verificación asimétrica."""

    contenido_pem: str

    def __post_init__(self) -> None:
        limpio = self.contenido_pem.strip()
        if "BEGIN PUBLIC KEY" not in limpio or "END PUBLIC KEY" not in limpio:
            raise ValorInvalidoError("La clave pública debe estar en formato PEM estándar.")
        object.__setattr__(self, "contenido_pem", limpio + "\n")

    def a_bytes(self) -> bytes:
        return self.contenido_pem.encode("utf-8")


@dataclass(frozen=True, slots=True)
class IdModelo:
    """Identificador semántico del modelo de IA bajo custodia."""

    valor: str

    def __post_init__(self) -> None:
        normalizado = self.valor.strip().lower()
        if not _RE_ID_MODELO.match(normalizado):
            raise ValorInvalidoError(
                f"Identificador de modelo inválido: '{self.valor}'. Use minúsculas, dígitos, '-', '_' o '.'."
            )
        object.__setattr__(self, "valor", normalizado)


@dataclass(frozen=True, slots=True)
class VersionSemantica:
    """Versión semántica del artefacto de IA (ej. 1.0.0)."""

    valor: str

    def __post_init__(self) -> None:
        limpio = self.valor.strip()
        if not _RE_SEMVER.match(limpio):
            raise ValorInvalidoError(f"Versión semántica inválida: '{self.valor}'. Ejemplo válido: '1.0.0'.")
        object.__setattr__(self, "valor", limpio)


@dataclass(frozen=True, slots=True)
class IdentidadActor:
    """Identidad de un nodo, investigador o autoridad autorizada en el registro."""

    identificador: str
    organizacion: str
    clave_publica: ClavePublicaPEM

    def __post_init__(self) -> None:
        identificador_limpio = self.identificador.strip()
        org_limpia = self.organizacion.strip()
        if len(identificador_limpio) < 3:
            raise ValorInvalidoError("El identificador del actor debe tener al menos 3 caracteres.")
        if len(org_limpia) < 2:
            raise ValorInvalidoError("La organización del actor debe tener al menos 2 caracteres.")
        object.__setattr__(self, "identificador", identificador_limpio)
        object.__setattr__(self, "organizacion", org_limpia)


@dataclass(frozen=True, slots=True)
class MarcaTemporalUTC:
    """Instante temporal normalizado en UTC en formato ISO-8601."""

    iso_utc: str

    def __post_init__(self) -> None:
        try:
            dt = datetime.fromisoformat(self.iso_utc)
        except ValueError as exc:
            raise ValorInvalidoError(f"Marca temporal ISO-8601 inválida: '{self.iso_utc}'.") from exc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        object.__setattr__(self, "iso_utc", dt.isoformat())
