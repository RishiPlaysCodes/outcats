"""Report exporters: CSV and print-ready PDF (via HTML).

- CSV: machine-readable, importable into any spreadsheet/SIEM.
- PDF: generates a print-optimized HTML file that opens in a browser and
  prints perfectly to PDF (File -> Print -> Save as PDF). Zero external
  dependencies; the CSS @media print rules handle everything.

We intentionally avoid requiring external libraries like wkhtmltopdf or
weasyprint so outcats stays zero-dependency and runs anywhere Python runs.
"""

from __future__ import annotations

import csv
import io
import time
from pathlib import Path

from .report import Report, Finding


def to_csv(report: Report) -> str:
    """Export findings as RFC-4180 CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "title", "severity", "status", "detail",
        "remediation", "references", "module", "target", "generated_at"
    ])
    generated = time.strftime("%Y-%m-%d %H:%M:%S",
                              time.localtime(report.generated_at))
    for f in report.findings:
        writer.writerow([
            f.id, f.title, f.severity.value, f.status.value,
            f.detail, f.remediation, "; ".join(f.references),
            report.module, report.target, generated,
        ])
    return buf.getvalue()


def to_pdf_html(report: Report) -> str:
    """Generate a print-optimized HTML file. The user opens it and prints to PDF.

    The output is a self-contained HTML page with:
    - @media print CSS that removes dark background and uses print-friendly layout
    - Page headers and footers via CSS
    - Automatic page breaks between large sections
    """
    base_html = report.to_html()
    # Inject print-friendly CSS before </style>
    print_css = """
    @media print {
      body { background: #fff !important; color: #111 !important; font-size: 11pt; }
      header { background: #fff !important; border-bottom: 2px solid #333 !important;
               position: static !important; }
      h1 { color: #111 !important; }
      .meta, .sub { color: #444 !important; }
      .cards { break-inside: avoid; }
      .card { background: #f5f5f5 !important; border: 1px solid #ccc !important;
              color: #111 !important; }
      .card .n { color: #111 !important; }
      .card .l { color: #444 !important; }
      table { font-size: 10pt; }
      th, td { border-bottom: 1px solid #ccc !important; color: #111 !important; }
      th { color: #444 !important; }
      .mono { color: #333 !important; }
      .detail { color: #555 !important; }
      .fix { color: #1a7a1a !important; }
      .refs { color: #666 !important; }
      .status, .sev { background: #eee !important; color: #333 !important;
                      border: 1px solid #999; }
      .status.fail, .sev.critical, .sev.high { border-color: #c00; color: #c00 !important; }
      .status.pass, .sev.low { border-color: #1a7a1a; color: #1a7a1a !important; }
      .status.warn, .sev.medium { border-color: #b38600; color: #b38600 !important; }
      tr { break-inside: avoid; }
      @page { margin: 1.5cm; size: A4 landscape; }
    }
    """
    return base_html.replace("</style>", print_css + "</style>")


def save_csv(report: Report, path: str) -> Path:
    p = Path(path)
    p.write_text(to_csv(report))
    return p


def save_pdf_html(report: Report, path: str) -> Path:
    p = Path(path)
    p.write_text(to_pdf_html(report))
    return p
