"""Adaptadores criptográficos concretos: SHA-256, firmas Ed25519 y reloj UTC."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cripto_ia_integridad.dominio.valores import (
    ClavePublicaPEM,
    FirmaDigital,
    HashSHA256,
    MarcaTemporalUTC,
)


class ServicioHashSHA256:
    """Implementación estándar SHA-256 con lectura en bloques para archivos."""

    _TAMANO_BLOQUE = 65536

    def calcular_bytes(self, contenido: bytes) -> HashSHA256:
        return HashSHA256(hashlib.sha256(contenido).hexdigest())

    def calcular_archivo(self, ruta_archivo: str) -> HashSHA256:
        ruta = Path(ruta_archivo)
        digest = hashlib.sha256()
        with ruta.open("rb") as archivo:
            while fragmento := archivo.read(self._TAMANO_BLOQUE):
                digest.update(fragmento)
        return HashSHA256(digest.hexdigest())


class FirmadorEd25519:
    """Firmador asimétrico basado en curva elíptica Ed25519."""

    def __init__(self, clave_privada: Ed25519PrivateKey) -> None:
        self._clave_privada = clave_privada

    @classmethod
    def generar_nuevo(cls) -> FirmadorEd25519:
        """Genera un par de claves Ed25519 criptográficamente seguro."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def desde_pem_privado(cls, ruta_pem: str, contrasena: bytes | None = None) -> FirmadorEd25519:
        contenido = Path(ruta_pem).read_bytes()
        clave = serialization.load_pem_private_key(contenido, password=contrasena)
        if not isinstance(clave, Ed25519PrivateKey):
            raise TypeError("La clave privada cargada no corresponde al algoritmo Ed25519.")
        return cls(clave)

    def guardar_pem_privado(self, ruta_pem: str) -> None:
        """Serializa la clave privada sin cifrado (solo para entorno experimental PoC)."""
        destino = Path(ruta_pem)
        destino.parent.mkdir(parents=True, exist_ok=True)
        pem = self._clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        destino.write_bytes(pem)

    def obtener_clave_publica(self) -> ClavePublicaPEM:
        pem = self._clave_privada.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return ClavePublicaPEM(pem.decode("utf-8"))

    def firmar(self, payload: bytes) -> FirmaDigital:
        firma_raw = self._clave_privada.sign(payload)
        return FirmaDigital.desde_bytes(firma_raw)


class VerificadorEd25519:
    """Verificador de firmas digitales Ed25519 mediante clave pública PEM."""

    def verificar(
        self,
        payload: bytes,
        firma: FirmaDigital,
        clave_publica: ClavePublicaPEM,
    ) -> bool:
        try:
            clave = serialization.load_pem_public_key(clave_publica.a_bytes())
            if not isinstance(clave, Ed25519PublicKey):
                return False
            clave.verify(firma.a_bytes(), payload)
            return True
        except (InvalidSignature, ValueError):
            return False


class RelojUTC:
    """Proveedor de marca temporal real del sistema en UTC."""

    def ahora_utc(self) -> MarcaTemporalUTC:
        return MarcaTemporalUTC(datetime.now(timezone.utc).isoformat())
