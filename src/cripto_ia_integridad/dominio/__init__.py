"""Capa de dominio puro del sistema de custodia criptográfica para modelos IA."""

from cripto_ia_integridad.dominio.bloque import BloqueAuditoria
from cripto_ia_integridad.dominio.cadena import CadenaCustodia, ResultadoVerificacionModelo
from cripto_ia_integridad.dominio.estados_modelo import (
    EstadoAprobado,
    EstadoComprometido,
    EstadoModelo,
    EstadoNoRegistrado,
    EstadoRegistrado,
    EstadoRevocado,
    FabricaEstadosModelo,
)
from cripto_ia_integridad.dominio.excepciones import (
    ActorNoAutorizadoError,
    CadenaCorruptaError,
    ErrorDeDominio,
    FirmaInvalidaError,
    IntegridadModeloError,
    ModeloNoRegistradoError,
    TransicionInvalidaError,
    ValorInvalidoError,
)
from cripto_ia_integridad.dominio.operaciones import (
    FabricaOperacionesCustodia,
    OperacionAprobacionModelo,
    OperacionCompromisoModelo,
    OperacionCustodia,
    OperacionGenesis,
    OperacionRegistroModelo,
    OperacionRevocacionModelo,
)
from cripto_ia_integridad.dominio.valores import (
    ClavePublicaPEM,
    FirmaDigital,
    HashSHA256,
    IdentidadActor,
    IdModelo,
    MarcaTemporalUTC,
    VersionSemantica,
)

__all__ = [
    "ActorNoAutorizadoError",
    "BloqueAuditoria",
    "CadenaCorruptaError",
    "CadenaCustodia",
    "ClavePublicaPEM",
    "ErrorDeDominio",
    "EstadoAprobado",
    "EstadoComprometido",
    "EstadoModelo",
    "EstadoNoRegistrado",
    "EstadoRegistrado",
    "EstadoRevocado",
    "FabricaEstadosModelo",
    "FabricaOperacionesCustodia",
    "FirmaDigital",
    "FirmaInvalidaError",
    "HashSHA256",
    "IdentidadActor",
    "IdModelo",
    "IntegridadModeloError",
    "MarcaTemporalUTC",
    "ModeloNoRegistradoError",
    "OperacionAprobacionModelo",
    "OperacionCompromisoModelo",
    "OperacionCustodia",
    "OperacionGenesis",
    "OperacionRegistroModelo",
    "OperacionRevocacionModelo",
    "ResultadoVerificacionModelo",
    "TransicionInvalidaError",
    "ValorInvalidoError",
    "VersionSemantica",
]
