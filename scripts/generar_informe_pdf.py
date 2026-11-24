"""Genera el informe técnico en formato PDF (A4) a partir del documento Markdown."""

from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
RUTA_MD = ROOT / "docs" / "INFORME_AVANCE_OE4_S2.md"
RUTA_PDF = ROOT / "docs" / "INFORME_AVANCE_OE4_S2.pdf"

COLOR_PRIMARIO = colors.HexColor("#08162b")
COLOR_SECUNDARIO = colors.HexColor("#0f3a66")
COLOR_ACENTO = colors.HexColor("#0284c7")
COLOR_TEXTO = colors.HexColor("#1e293b")
COLOR_SUAVE = colors.HexColor("#64748b")
COLOR_FONDO_CARD = colors.HexColor("#f1f5f9")
COLOR_BORDE = colors.HexColor("#cbd5e1")


def _registrar_fuentes() -> tuple[str, str]:
    """Registra Arial y Consolas TrueType para soporte UTF-8 completo."""
    fonts_dir = Path(r"C:\Windows\Fonts")
    arial = fonts_dir / "arial.ttf"
    arial_bd = fonts_dir / "arialbd.ttf"
    arial_it = fonts_dir / "ariali.ttf"
    arial_bi = fonts_dir / "arialbi.ttf"
    consola = fonts_dir / "consola.ttf"

    if arial.exists() and arial_bd.exists() and arial_it.exists() and arial_bi.exists():
        pdfmetrics.registerFont(TTFont("DocSans", str(arial)))
        pdfmetrics.registerFont(TTFont("DocSans-Bold", str(arial_bd)))
        pdfmetrics.registerFont(TTFont("DocSans-Italic", str(arial_it)))
        pdfmetrics.registerFont(TTFont("DocSans-BoldItalic", str(arial_bi)))
        pdfmetrics.registerFontFamily(
            "DocSans",
            normal="DocSans",
            bold="DocSans-Bold",
            italic="DocSans-Italic",
            boldItalic="DocSans-BoldItalic",
        )
        fuente_sans = "DocSans"
    else:
        fuente_sans = "Helvetica"

    if consola.exists():
        pdfmetrics.registerFont(TTFont("DocMono", str(consola)))
        fuente_mono = "DocMono"
    else:
        fuente_mono = "Courier"

    return fuente_sans, fuente_mono


def _formatear_inline(texto: str, fuente_mono: str) -> str:
    """Convierte énfasis Markdown básico y símbolos matemáticos a markup ReportLab."""
    limpio = texto.replace(r"$\rightarrow$", "→").replace("$M$-de-$N$", "M-de-N")
    segmentos_codigo: list[str] = []

    def _guardar_codigo(match: re.Match[str]) -> str:
        contenido = html.escape(match.group(1))
        segmentos_codigo.append(f'<font name="{fuente_mono}" size="8.5" color="#0f3a66">{contenido}</font>')
        return f"@@CODE{len(segmentos_codigo) - 1}@@"

    limpio = re.sub(r"`([^`]+)`", _guardar_codigo, limpio)
    limpio = html.escape(limpio)
    limpio = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", limpio)
    limpio = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", limpio)

    for idx, bloque in enumerate(segmentos_codigo):
        limpio = limpio.replace(f"@@CODE{idx}@@", bloque)
    return limpio


def _construir_estilos(fuente_sans: str) -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle(
            "DocH1",
            parent=base["Heading1"],
            fontName=f"{fuente_sans}-Bold" if fuente_sans == "DocSans" else "Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=COLOR_PRIMARIO,
            spaceBefore=6,
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "DocH2",
            parent=base["Heading2"],
            fontName=f"{fuente_sans}-Bold" if fuente_sans == "DocSans" else "Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=COLOR_SECUNDARIO,
            spaceBefore=9,
            spaceAfter=4,
        ),
        "h3": ParagraphStyle(
            "DocH3",
            parent=base["Heading3"],
            fontName=f"{fuente_sans}-Bold" if fuente_sans == "DocSans" else "Helvetica-Bold",
            fontSize=10.2,
            leading=13,
            textColor=COLOR_ACENTO,
            spaceBefore=6,
            spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "DocBody",
            parent=base["Normal"],
            fontName=fuente_sans,
            fontSize=9.5,
            leading=13,
            textColor=COLOR_TEXTO,
            alignment=TA_JUSTIFY,
            spaceAfter=4,
        ),
        "meta": ParagraphStyle(
            "DocMeta",
            parent=base["Normal"],
            fontName=fuente_sans,
            fontSize=9.0,
            leading=12.5,
            textColor=COLOR_TEXTO,
            alignment=TA_LEFT,
            spaceAfter=1.5,
        ),
        "bullet": ParagraphStyle(
            "DocBullet",
            parent=base["Normal"],
            fontName=fuente_sans,
            fontSize=9.3,
            leading=12.8,
            textColor=COLOR_TEXTO,
            leftIndent=14,
            firstLineIndent=-10,
            alignment=TA_JUSTIFY,
            spaceAfter=2.5,
        ),
        "th": ParagraphStyle(
            "DocTH",
            parent=base["Normal"],
            fontName=f"{fuente_sans}-Bold" if fuente_sans == "DocSans" else "Helvetica-Bold",
            fontSize=8.8,
            leading=11.5,
            textColor=colors.white,
            alignment=TA_LEFT,
        ),
        "td": ParagraphStyle(
            "DocTD",
            parent=base["Normal"],
            fontName=fuente_sans,
            fontSize=8.5,
            leading=11.5,
            textColor=COLOR_TEXTO,
            alignment=TA_LEFT,
        ),
        "td_center": ParagraphStyle(
            "DocTDCenter",
            parent=base["Normal"],
            fontName=f"{fuente_sans}-Bold" if fuente_sans == "DocSans" else "Helvetica-Bold",
            fontSize=8.5,
            leading=11.5,
            textColor=COLOR_SECUNDARIO,
            alignment=TA_CENTER,
        ),
    }


def _dibujar_encabezado_pie(canvas, doc, fuente_sans: str) -> None:
    canvas.saveState()
    ancho, alto = A4
    if doc.page > 1:
        canvas.setFont(fuente_sans, 8)
        canvas.setFillColor(COLOR_SUAVE)
        canvas.drawString(
            doc.leftMargin,
            alto - 1.2 * cm,
            "Proyecto: Criptografía e Inteligencia Artificial · Prototipo Blockchain v0.1 (OE2 / OE4)",
        )
        canvas.setStrokeColor(COLOR_BORDE)
        canvas.setLineWidth(0.5)
        canvas.line(doc.leftMargin, alto - 1.35 * cm, ancho - doc.rightMargin, alto - 1.35 * cm)

    canvas.setStrokeColor(COLOR_BORDE)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 1.35 * cm, ancho - doc.rightMargin, 1.35 * cm)
    canvas.setFont(fuente_sans, 8)
    canvas.setFillColor(COLOR_SUAVE)
    canvas.drawString(doc.leftMargin, 0.9 * cm, "CT Martin CRESPO · Informe de Avance Técnico")
    canvas.drawRightString(ancho - doc.rightMargin, 0.9 * cm, f"Página {doc.page}")
    canvas.restoreState()


def generar_pdf() -> Path:
    fuente_sans, fuente_mono = _registrar_fuentes()
    estilos = _construir_estilos(fuente_sans)
    lineas = RUTA_MD.read_text(encoding="utf-8").splitlines()

    doc = SimpleDocTemplate(
        str(RUTA_PDF),
        pagesize=A4,
        leftMargin=1.65 * cm,
        rightMargin=1.65 * cm,
        topMargin=1.6 * cm,
        bottomMargin=1.6 * cm,
        title="Informe de Avance Técnico - Criptografía e Inteligencia Artificial",
        author="CT Martin CRESPO",
    )
    ancho_util = A4[0] - doc.leftMargin - doc.rightMargin
    elementos: list = []

    i = 0
    en_bloque_meta = False
    lineas_meta: list[str] = []

    def _vaciar_meta() -> None:
        nonlocal en_bloque_meta, lineas_meta
        if not lineas_meta:
            return
        parrafos = [[Paragraph(_formatear_inline(m, fuente_mono), estilos["meta"])] for m in lineas_meta]
        caja = Table(parrafos, colWidths=[ancho_util])
        caja.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_FONDO_CARD),
                    ("BOX", (0, 0), (-1, -1), 0.75, COLOR_BORDE),
                    ("LINEBEFORE", (0, 0), (0, -1), 3.0, COLOR_ACENTO),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        elementos.append(caja)
        elementos.append(Spacer(1, 6))
        lineas_meta = []
        en_bloque_meta = False

    while i < len(lineas):
        linea = lineas[i].strip()

        if not linea:
            _vaciar_meta()
            i += 1
            continue

        # Imagen Markdown
        m_img = re.match(r"^!\[([^\]]*)\]\(([^)]+)\)$", linea)
        if m_img:
            _vaciar_meta()
            ruta_img = (RUTA_MD.parent / m_img.group(2)).resolve()
            if ruta_img.exists():
                alto_img = ancho_util * (600 / 1600)
                elementos.append(Image(str(ruta_img), width=ancho_util, height=alto_img))
                elementos.append(Spacer(1, 10))
            i += 1
            continue

        # Regla horizontal
        if linea == "---":
            _vaciar_meta()
            elementos.append(Spacer(1, 4))
            elementos.append(HRFlowable(width="100%", thickness=0.8, color=COLOR_BORDE))
            elementos.append(Spacer(1, 6))
            i += 1
            continue

        # Encabezados
        if linea.startswith("# "):
            _vaciar_meta()
            elementos.append(Paragraph(_formatear_inline(linea[2:], fuente_mono), estilos["h1"]))
            en_bloque_meta = True
            i += 1
            continue
        if linea.startswith("## "):
            _vaciar_meta()
            elementos.append(Paragraph(_formatear_inline(linea[3:], fuente_mono), estilos["h2"]))
            i += 1
            continue
        if linea.startswith("### "):
            _vaciar_meta()
            elementos.append(Paragraph(_formatear_inline(linea[4:], fuente_mono), estilos["h3"]))
            i += 1
            continue

        # Bloque de metadatos iniciales
        if en_bloque_meta and linea.startswith("**"):
            lineas_meta.append(linea)
            i += 1
            continue
        _vaciar_meta()

        # Tablas Markdown
        if linea.startswith("|"):
            filas_raw: list[list[str]] = []
            while i < len(lineas) and lineas[i].strip().startswith("|"):
                fila_txt = lineas[i].strip()
                celdas = [c.strip() for c in fila_txt.strip("|").split("|")]
                if not all(re.match(r"^:?-+:?$", c) for c in celdas):
                    filas_raw.append(celdas)
                i += 1

            if filas_raw:
                tabla_data = []
                for idx_fila, fila in enumerate(filas_raw):
                    if idx_fila == 0:
                        tabla_data.append(
                            [Paragraph(_formatear_inline(c, fuente_mono), estilos["th"]) for c in fila]
                        )
                    else:
                        tabla_data.append(
                            [
                                Paragraph(
                                    _formatear_inline(c, fuente_mono),
                                    estilos["td_center"] if col_idx in (1, 2) else estilos["td"],
                                )
                                for col_idx, c in enumerate(fila)
                            ]
                        )
                anchos_col = [
                    ancho_util * 0.28,
                    ancho_util * 0.14,
                    ancho_util * 0.12,
                    ancho_util * 0.46,
                ]
                tabla = Table(tabla_data, colWidths=anchos_col, repeatRows=1)
                tabla.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARIO),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_FONDO_CARD]),
                            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDE),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 0), (-1, -1), 5),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ]
                    )
                )
                elementos.append(Spacer(1, 4))
                elementos.append(tabla)
                elementos.append(Spacer(1, 8))
            continue

        # Listas numeradas o con viñetas
        m_num = re.match(r"^(\d+\.)\s+(.*)$", linea)
        if m_num:
            texto_item = f"<b>{m_num.group(1)}</b> {_formatear_inline(m_num.group(2), fuente_mono)}"
            elementos.append(Paragraph(texto_item, estilos["bullet"]))
            i += 1
            continue
        if linea.startswith("* ") or linea.startswith("- "):
            texto_item = f"• {_formatear_inline(linea[2:], fuente_mono)}"
            elementos.append(Paragraph(texto_item, estilos["bullet"]))
            i += 1
            continue

        # Párrafo estándar
        elementos.append(Paragraph(_formatear_inline(linea, fuente_mono), estilos["body"]))
        i += 1

    _vaciar_meta()
    doc.build(
        elementos,
        onFirstPage=lambda c, d: _dibujar_encabezado_pie(c, d, fuente_sans),
        onLaterPages=lambda c, d: _dibujar_encabezado_pie(c, d, fuente_sans),
    )
    return RUTA_PDF


if __name__ == "__main__":
    salida = generar_pdf()
    print(f"PDF generado correctamente: {salida}")
