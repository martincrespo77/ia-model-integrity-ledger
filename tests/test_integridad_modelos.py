"""Suite de pruebas unitarias y de integración para el prototipo Blockchain + Ed25519."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cripto_ia_integridad.aplicacion.servicio_custodia import ServicioCustodiaModelos
from cripto_ia_integridad.dominio.estados_modelo import (
    EstadoAprobado,
    EstadoComprometido,
    EstadoNoRegistrado,
    EstadoRegistrado,
    EstadoRevocado,
)
from cripto_ia_integridad.dominio.excepciones import (
    ActorNoAutorizadoError,
    CadenaCorruptaError,
    FirmaInvalidaError,
    IntegridadModeloError,
    ModeloNoRegistradoError,
    TransicionInvalidaError,
    ValorInvalidoError,
)
from cripto_ia_integridad.dominio.valores import (
    HashSHA256,
    IdentidadActor,
    IdModelo,
    VersionSemantica,
)
from cripto_ia_integridad.infraestructura.cripto_ed25519 import (
    FirmadorEd25519,
    RelojUTC,
    ServicioHashSHA256,
    VerificadorEd25519,
)
from cripto_ia_integridad.infraestructura.modelo_ia_demo import (
    corromper_un_byte_artefacto,
    ejecutar_inferencia_pt,
    entrenar_y_guardar_modelo_demo,
)
from cripto_ia_integridad.infraestructura.repositorio_json import RepositorioCadenaJSON


class TestValueObjectsYEstados(unittest.TestCase):
    """Verifica invariantes de construcción y máquina de estados polimórfica."""

    def test_hash_sha256_rechaza_longitud_invalida(self) -> None:
        with self.assertRaises(ValorInvalidoError):
            HashSHA256("abc123")

    def test_version_semantica_valida_y_normalizacion(self) -> None:
        version = VersionSemantica(" 1.2.3-rc1 ")
        self.assertEqual(version.valor, "1.2.3-rc1")
        with self.assertRaises(ValorInvalidoError):
            VersionSemantica("v1")

    def test_ciclo_de_vida_estados_bloquea_transiciones_ilegales(self) -> None:
        estado = EstadoNoRegistrado()
        with self.assertRaises(ModeloNoRegistradoError):
            estado.aprobar()
        with self.assertRaises(ModeloNoRegistradoError):
            estado.validar_habilitado_para_inferencia()

        registrado = estado.registrar()
        self.assertIsInstance(registrado, EstadoRegistrado)
        with self.assertRaises(TransicionInvalidaError):
            registrado.validar_habilitado_para_inferencia()

        aprobado = registrado.aprobar()
        self.assertIsInstance(aprobado, EstadoAprobado)
        aprobado.validar_habilitado_para_inferencia()

        revocado = aprobado.revocar()
        self.assertIsInstance(revocado, EstadoRevocado)
        with self.assertRaises(TransicionInvalidaError):
            revocado.aprobar()

        comprometido = aprobado.marcar_comprometido()
        self.assertIsInstance(comprometido, EstadoComprometido)
        with self.assertRaises(TransicionInvalidaError):
            comprometido.registrar()
        with self.assertRaises(IntegridadModeloError):
            comprometido.validar_habilitado_para_inferencia()


class TestEscenariosIntegridadCustodia(unittest.TestCase):
    """Pruebas de extremo a extremo con artefacto PyTorch real y firmas Ed25519."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name)
        self.ruta_ledger = self.base / "ledger.json"
        self.ruta_modelo = self.base / "modelo.pt"

        self.servicio_hash = ServicioHashSHA256()
        self.verificador = VerificadorEd25519()
        self.servicio = ServicioCustodiaModelos(
            repositorio=RepositorioCadenaJSON(str(self.ruta_ledger)),
            servicio_hash=self.servicio_hash,
            verificador=self.verificador,
            reloj=RelojUTC(),
        )

        self.firmador_autoridad = FirmadorEd25519.generar_nuevo()
        self.autoridad = IdentidadActor(
            identificador="autoridad-central",
            organizacion="FIE",
            clave_publica=self.firmador_autoridad.obtener_clave_publica(),
        )
        self.firmador_lab = FirmadorEd25519.generar_nuevo()
        self.laboratorio = IdentidadActor(
            identificador="lab-modelos",
            organizacion="FIE",
            clave_publica=self.firmador_lab.obtener_clave_publica(),
        )
        self.firmador_intruso = FirmadorEd25519.generar_nuevo()
        self.intruso = IdentidadActor(
            identificador="intruso-externo",
            organizacion="Externo",
            clave_publica=self.firmador_intruso.obtener_clave_publica(),
        )

        self.servicio.inicializar_red(
            autoridad_inicial=self.autoridad,
            firmador_inicial=self.firmador_autoridad,
            actores_adicionales=[self.laboratorio],
        )
        entrenar_y_guardar_modelo_demo(str(self.ruta_modelo), epocas=60)
        self.id_modelo = IdModelo("clasificador-defensa")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_escenario_1_flujo_legitimo_habilita_inferencia(self) -> None:
        self.servicio.registrar_modelo_desde_archivo(
            id_modelo=self.id_modelo,
            version=VersionSemantica("1.0.0"),
            ruta_artefacto=str(self.ruta_modelo),
            actor=self.laboratorio,
            firmador=self.firmador_lab,
        )
        self.servicio.aprobar_modelo(
            id_modelo=self.id_modelo,
            actor=self.autoridad,
            firmador=self.firmador_autoridad,
        )
        resultado = self.servicio.verificar_artefacto_previo_inferencia(
            id_modelo=self.id_modelo,
            ruta_artefacto=str(self.ruta_modelo),
        )
        self.assertTrue(resultado.integro)
        self.assertEqual(resultado.total_bloques_auditados, 3)
        self.assertEqual(resultado.estado_codigo, "APROBADO")

        clase, probs = ejecutar_inferencia_pt(str(self.ruta_modelo), [0.2, 0.25, 0.1, 0.3])
        self.assertIn(clase, (0, 1))
        self.assertAlmostEqual(sum(probs), 1.0, places=3)

    def test_escenario_2_alteracion_de_un_byte_bloquea_inferencia_y_registra_incidente(self) -> None:
        self.servicio.registrar_modelo_desde_archivo(
            id_modelo=self.id_modelo,
            version=VersionSemantica("1.0.0"),
            ruta_artefacto=str(self.ruta_modelo),
            actor=self.laboratorio,
            firmador=self.firmador_lab,
        )
        self.servicio.aprobar_modelo(
            id_modelo=self.id_modelo,
            actor=self.autoridad,
            firmador=self.firmador_autoridad,
        )

        corromper_un_byte_artefacto(str(self.ruta_modelo))

        with self.assertRaises(IntegridadModeloError):
            self.servicio.verificar_artefacto_previo_inferencia(
                id_modelo=self.id_modelo,
                ruta_artefacto=str(self.ruta_modelo),
                actor_auditor=self.autoridad,
                firmador_auditor=self.firmador_autoridad,
            )

        cadena_actualizada = RepositorioCadenaJSON(str(self.ruta_ledger)).cargar()
        self.assertEqual(len(cadena_actualizada.bloques), 4)
        self.assertEqual(cadena_actualizada.estado_de_modelo(self.id_modelo).codigo, "COMPROMETIDO")

    def test_escenario_3_actor_no_autorizado_y_firma_falsa_son_rechazados(self) -> None:
        with self.assertRaises(ActorNoAutorizadoError):
            self.servicio.registrar_modelo_desde_archivo(
                id_modelo=self.id_modelo,
                version=VersionSemantica("1.0.0"),
                ruta_artefacto=str(self.ruta_modelo),
                actor=self.intruso,
                firmador=self.firmador_intruso,
            )

        with self.assertRaises(FirmaInvalidaError):
            self.servicio.registrar_modelo_desde_archivo(
                id_modelo=self.id_modelo,
                version=VersionSemantica("1.0.0"),
                ruta_artefacto=str(self.ruta_modelo),
                actor=self.laboratorio,
                firmador=self.firmador_intruso,
            )

        self.assertEqual(self.servicio.auditar_cadena_completa(), 1)

    def test_escenario_4_manipulacion_del_ledger_json_es_detectada(self) -> None:
        self.servicio.registrar_modelo_desde_archivo(
            id_modelo=self.id_modelo,
            version=VersionSemantica("1.0.0"),
            ruta_artefacto=str(self.ruta_modelo),
            actor=self.laboratorio,
            firmador=self.firmador_lab,
        )

        datos = json.loads(self.ruta_ledger.read_text(encoding="utf-8"))
        datos["bloques"][1]["observacion"] = "Observación alterada por atacante"
        self.ruta_ledger.write_text(json.dumps(datos, indent=2), encoding="utf-8")

        with self.assertRaises(CadenaCorruptaError):
            self.servicio.auditar_cadena_completa()


if __name__ == "__main__":
    unittest.main(verbosity=2)
