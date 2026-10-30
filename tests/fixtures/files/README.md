# Benign document fixtures (SYNTHETIC content)

Real files written by a real Office suite, used to check that the File Inspector's
parsers read genuine formats and that ordinary documents are *not* flagged.

They were made with LibreOffice 24.2.7.2 (`soffice --headless --convert-to …`) from
two synthetic inputs: a short "garden club newsletter" text and a three-row CSV.
They contain no macros, links or embedded objects.

| File | Format |
| --- | --- |
| `benign.doc` | Word 97–2003 (OLE2 compound file) |
| `benign.xls` | Excel 97–2003 (OLE2, BIFF8 workbook) |
| `benign.docx` | Word (Office Open XML) |
| `benign.xlsx` | Excel (Office Open XML) |
| `benign.pdf` | PDF 1.7 with compressed streams and an embedded font |

Suspicious-looking samples (macro droppers, auto-run PDFs, disguised executables)
are **not** committed. `tests/synth.py` builds them at test time with harmless
content, so antivirus on your machine has nothing to quarantine.
