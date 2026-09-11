"""Bilingual report generator (Ch.5 5.6.5, UC-6).

Renders an assessment report from stored findings into HTML and (via reportlab)
PDF, parameterised by language (en/ar) and depth (executive/technical/full).
The five sections follow the design: executive summary, findings register,
Mode 3 narrative, remediation plan mapped to ECC controls, compliance appendix.
Arabic renders right-to-left. Each report is content-hashed for the Report row.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

# --- Arabic support: register a bundled Arabic font and shape RTL text ------
_AR_FONT = "ArabicNaskh"
_ar_ready = False
try:
    _font_path = Path(__file__).resolve().parent.parent / "data" / "fonts" / "KacstNaskh.ttf"
    if _font_path.exists():
        pdfmetrics.registerFont(TTFont(_AR_FONT, str(_font_path)))
        _ar_ready = True
    import arabic_reshaper
    from bidi.algorithm import get_display
except Exception:  # noqa: BLE001
    _ar_ready = False


def _shape_ar(text: str) -> str:
    """Reshape + bidi-reorder Arabic so glyphs join and read right-to-left."""
    if not _ar_ready or not text:
        return text
    try:
        return get_display(arabic_reshaper.reshape(text))
    except Exception:  # noqa: BLE001
        return text

_LABELS = {
    "en": {"title": "ASAA Security Assessment Report", "target": "Target",
           "exec": "1. Executive Summary", "findings": "2. Findings Register",
           "narrative": "3. Attack-Path Narrative (Mode 3, AI-assisted)",
           "remediation": "4. Remediation Plan (ECC-2:2024 mapped)",
           "compliance": "5. Compliance Mapping", "sev": "Severity", "id": "ID",
           "finding": "Finding", "cvss": "CVSS", "generated": "Generated"},
    "ar": {"title": "تقرير تقييم أمني ASAA", "target": "الهدف",
           "exec": "1. الملخص التنفيذي", "findings": "2. سجل النتائج",
           "narrative": "3. سرد مسار الهجوم (الوضع 3، بمساعدة الذكاء الاصطناعي)",
           "remediation": "4. خطة المعالجة (وفق ECC-2:2024)",
           "compliance": "5. مطابقة الامتثال", "sev": "الخطورة", "id": "المعرف",
           "finding": "النتيجة", "cvss": "CVSS", "generated": "تاريخ الإصدار"},
}

_SEV_COLOR = {"critical": colors.HexColor("#7f1d1d"), "high": colors.HexColor("#b91c1c"),
              "medium": colors.HexColor("#b45309"), "low": colors.HexColor("#3f6212"),
              "info": colors.HexColor("#334155")}


def _hash(data: dict) -> str:
    return hashlib.sha256(repr(sorted(data.items())).encode()).hexdigest()[:16]


def generate_pdf(report_data: dict, out_dir: Path, language: str = "en",
                 depth: str = "full") -> tuple[str, str]:
    L = dict(_LABELS.get(language, _LABELS["en"]))
    rtl = language == "ar"
    if rtl:
        L = {k: _shape_ar(v) for k, v in L.items()}
    ar_font = _AR_FONT if (rtl and _ar_ready) else "Helvetica"
    out_dir.mkdir(parents=True, exist_ok=True)
    tgt = report_data["target"]
    fname = f"asaa_report_{tgt['name'].replace(' ', '_')}_{language}.pdf"
    path = out_dir / fname

    styles = getSampleStyleSheet()
    align = 2 if rtl else 0  # 2=right
    h = ParagraphStyle("h", parent=styles["Heading2"], textColor=colors.HexColor("#0f766e"), alignment=align, fontName=ar_font)
    body = ParagraphStyle("b", parent=styles["BodyText"], alignment=align, leading=15, fontName=ar_font)
    title = ParagraphStyle("t", parent=styles["Title"], alignment=1, textColor=colors.HexColor("#0f172a"), fontName=ar_font)

    doc = SimpleDocTemplate(str(path), pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    story = [Paragraph(L["title"], title),
             Paragraph(f"{L['target']}: {tgt['name']} — {tgt['url']}", body),
             Paragraph(f"{L['generated']}: {dt.date.today().isoformat()}", body),
             Spacer(1, 0.5 * cm)]

    # 1. Executive summary
    story += [Paragraph(L["exec"], h), Paragraph(report_data["executive"], body), Spacer(1, 0.4 * cm)]

    # 2. Findings register
    story.append(Paragraph(L["findings"], h))
    rows = [[L["id"], L["finding"], L["sev"], L["cvss"]]]
    for f in report_data["findings"]:
        rows.append([f["identifier"], f["title"], f["severity"].upper(), f.get("cvss") or "-"])
    table = Table(rows, colWidths=[3 * cm, 8.5 * cm, 2.5 * cm, 2 * cm])
    style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTNAME", (0, 0), (-1, 0), ar_font),
             ("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")])]
    for i, f in enumerate(report_data["findings"], 1):
        style.append(("TEXTCOLOR", (2, i), (2, i), _SEV_COLOR.get(f["severity"], colors.black)))
    table.setStyle(TableStyle(style))
    story += [table, Spacer(1, 0.4 * cm)]

    # 3. Narrative
    if report_data.get("narrative") and depth != "executive":
        story += [Paragraph(L["narrative"], h), Paragraph(report_data["narrative"].replace("\n", "<br/>"), body), Spacer(1, 0.4 * cm)]

    # 4. Remediation
    story.append(Paragraph(L["remediation"], h))
    for r in report_data.get("remediation", []):
        story.append(Paragraph(f"• {r['action']} <b>[{r['ecc']}]</b>", body))
    story.append(Spacer(1, 0.4 * cm))

    # 5. Compliance mapping
    story.append(Paragraph(L["compliance"], h))
    story.append(Paragraph(report_data.get("compliance", ""), body))

    doc.build(story)
    return str(path), _hash(report_data)
