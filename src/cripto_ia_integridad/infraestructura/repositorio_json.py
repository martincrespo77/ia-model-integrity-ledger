"""Adaptador de persistencia JSON legible para la cadena de custodia."""

from __future__ import annotations

import json
from pathlib import Path

from cripto_ia_integridad.dominio.bloque import BloqueAuditoria
from cripto_ia_integridad.dominio.cadena import CadenaCustodia
from cripto_ia_integridad.dominio.operaciones import FabricaOperacionesCustodia
from cripto_ia_integridad.dominio.valores import (
    ClavePublicaPEM,
    FirmaDigital,
    HashSHA256,
    IdentidadActor,
    IdModelo,
    MarcaTemporalUTC,
    VersionSemantica,
)


class RepositorioCadenaJSON:
    """Persiste y reconstruye `CadenaCustodia` en un archivo JSON auditable."""

    def __init__(self, ruta_ledger: str) -> None:
        self._ruta = Path(ruta_ledger)

    @property
    def ruta(self) -> Path:
        return self._ruta

    def existe(self) -> bool:
        return self._ruta.exists()

    def guardar(self, cadena: CadenaCustodia) -> None:
        self._ruta.parent.mkdir(parents=True, exist_ok=True)
        datos = {
            "version_esquema": "0.1",
            "actores_autorizados": [
                {
                    "identificador": actor.identificador,
                    "organizacion": actor.organizacion,
                    "clave_publica_pem": actor.clave_publica.contenido_pem,
                }
                for actor in cadena.actores_autorizados
            ],
            "bloques": [
                {
                    "indice": bloque.indice,
                    "marca_temporal": bloque.marca_temporal.iso_utc,
                    "operacion": bloque.operacion.codigo,
                    "id_modelo": bloque.id_modelo.valor,
                    "version_modelo": bloque.version_modelo.valor,
                    "hash_artefacto": bloque.hash_artefacto.valor,
                    "hash_anterior": bloque.hash_anterior.valor,
                    "actor": {
                        "identificador": bloque.actor.identificador,
                        "organizacion": bloque.actor.organizacion,
                        "clave_publica_pem": bloque.actor.clave_publica.contenido_pem,
                    },
                    "observacion": bloque.observacion,
                    "firma": bloque.firma.hex_firma,
                    "hash_bloque": bloque.hash_bloque.valor,
                }
                for bloque in cadena.bloques
            ],
        }
        self._ruta.write_text(json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8")

    def cargar(self) -> CadenaCustodia:
        contenido = json.loads(self._ruta.read_text(encoding="utf-8"))
        actores = [
            IdentidadActor(
                identificador=item["identificador"],
                organizacion=item["organizacion"],
                clave_publica=ClavePublicaPEM(item["clave_publica_pem"]),
            )
            for item in contenido["actores_autorizados"]
        ]
        bloques = [
            BloqueAuditoria(
                indice=int(item["indice"]),
                marca_temporal=MarcaTemporalUTC(item["marca_temporal"]),
                operacion=FabricaOperacionesCustodia.desde_codigo(item["operacion"]),
                id_modelo=IdModelo(item["id_modelo"]),
                version_modelo=VersionSemantica(item["version_modelo"]),
                hash_artefacto=HashSHA256(item["hash_artefacto"]),
                hash_anterior=HashSHA256(item["hash_anterior"]),
                actor=IdentidadActor(
                    identificador=item["actor"]["identificador"],
                    organizacion=item["actor"]["organizacion"],
                    clave_publica=ClavePublicaPEM(item["actor"]["clave_publica_pem"]),
                ),
                observacion=item["observacion"],
                firma=FirmaDigital(item["firma"]),
                hash_bloque=HashSHA256(item["hash_bloque"]),
            )
            for item in contenido["bloques"]
        ]
        return CadenaCustodia.reconstruir(bloques=bloques, actores_autorizados=actores)
