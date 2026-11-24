"""Excepciones semánticas del dominio de custodia criptográfica."""


class ErrorDeDominio(Exception):
    """Clase base para todas las violaciones de invariantes del dominio."""


class ValorInvalidoError(ErrorDeDominio):
    """Se lanza cuando un Value Object recibe datos fuera de formato o rango."""


class TransicionInvalidaError(ErrorDeDominio):
    """Se lanza ante una transición prohibida en el ciclo de vida de un modelo."""


class FirmaInvalidaError(ErrorDeDominio):
    """Se lanza cuando una firma digital no corresponde al emisor o payload."""


class ActorNoAutorizadoError(ErrorDeDominio):
    """Se lanza cuando una identidad no posee permiso para operar sobre la cadena."""


class CadenaCorruptaError(ErrorDeDominio):
    """Se lanza cuando se detecta ruptura de encadenamiento o hash inconsistente."""


class IntegridadModeloError(ErrorDeDominio):
    """Se lanza cuando el artefacto de IA no coincide con el hash registrado."""


class ModeloNoRegistradoError(ErrorDeDominio):
    """Se lanza al consultar o verificar un modelo inexistente en la cadena."""
