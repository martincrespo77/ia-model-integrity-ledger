"""Modelo de IA real (PyTorch) para demostración de custodia e integridad en Ciberdefensa."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import torch
from torch import nn


class DetectorAnomaliasRed(nn.Module):
    """Red neuronal liviana (MLP) para clasificación binaria de tráfico de red (Normal vs. Anómalo)."""

    def __init__(self, dimension_entrada: int = 4) -> None:
        super().__init__()
        self.capas = nn.Sequential(
            nn.Linear(dimension_entrada, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 2),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.capas(x)


@dataclass(frozen=True, slots=True)
class ResumenEntrenamientoDemo:
    """Métricas obtenidas al entrenar el modelo demostrativo."""

    ruta_artefacto: str
    tamano_bytes: int
    precision_entrenamiento: float
    epocas: int


def entrenar_y_guardar_modelo_demo(
    ruta_salida_pt: str,
    *,
    semilla: int = 42,
    epocas: int = 120,
) -> ResumenEntrenamientoDemo:
    """Entrena de forma determinística un clasificador PyTorch y lo guarda en disco."""
    torch.manual_seed(semilla)

    # Datos sintéticos reproducibles: 4 características normalizadas [0, 1]
    # [tasa_paquetes, proporcion_bytes, fallos_autenticacion, entropia_carga]
    n_por_clase = 120
    trafico_normal = torch.clamp(
        torch.randn(n_por_clase, 4) * 0.12 + torch.tensor([0.25, 0.30, 0.08, 0.35]),
        0.0,
        1.0,
    )
    trafico_anomalo = torch.clamp(
        torch.randn(n_por_clase, 4) * 0.12 + torch.tensor([0.80, 0.75, 0.78, 0.85]),
        0.0,
        1.0,
    )
    x = torch.cat([trafico_normal, trafico_anomalo], dim=0)
    y = torch.cat(
        [
            torch.zeros(n_por_clase, dtype=torch.long),
            torch.ones(n_por_clase, dtype=torch.long),
        ],
        dim=0,
    )

    modelo = DetectorAnomaliasRed()
    optimizador = torch.optim.Adam(modelo.parameters(), lr=0.03)
    criterio = nn.CrossEntropyLoss()

    modelo.train()
    for _ in range(epocas):
        optimizador.zero_grad()
        salida = modelo(x)
        perdida = criterio(salida, y)
        perdida.backward()
        optimizador.step()

    modelo.eval()
    with torch.no_grad():
        predicciones = modelo(x).argmax(dim=1)
        precision = float((predicciones == y).float().mean().item())

    destino = Path(ruta_salida_pt)
    destino.parent.mkdir(parents=True, exist_ok=True)
    torch.save(modelo.state_dict(), destino)

    return ResumenEntrenamientoDemo(
        ruta_artefacto=str(destino),
        tamano_bytes=destino.stat().st_size,
        precision_entrenamiento=round(precision, 4),
        epocas=epocas,
    )


def ejecutar_inferencia_pt(ruta_modelo_pt: str, muestra: list[float]) -> tuple[int, list[float]]:
    """Carga los pesos verificados y ejecuta inferencia sobre una muestra de telemetría."""
    modelo = DetectorAnomaliasRed(dimension_entrada=len(muestra))
    estado = torch.load(ruta_modelo_pt, map_location="cpu", weights_only=True)
    modelo.load_state_dict(estado)
    modelo.eval()
    with torch.no_grad():
        tensor_entrada = torch.tensor([muestra], dtype=torch.float32)
        logits = modelo(tensor_entrada)
        probabilidades = torch.softmax(logits, dim=1)[0].tolist()
        clase = int(torch.argmax(logits, dim=1).item())
    return clase, [round(p, 4) for p in probabilidades]


def corromper_un_byte_artefacto(ruta_modelo_pt: str, desplazamiento_desde_fin: int = 32) -> int:
    """Altera exactamente 1 byte de los pesos guardados para simular manipulación silenciosa."""
    ruta = Path(ruta_modelo_pt)
    datos = bytearray(ruta.read_bytes())
    indice = max(0, len(datos) - desplazamiento_desde_fin)
    datos[indice] ^= 0x01
    ruta.write_bytes(bytes(datos))
    return indice
