# Academic Workbench

Clinical Data Studio can now act as a practical academic case-series notebook in addition to a structured REDCap-like EDC.

## What It Does

1. Capture messy clinical evidence in **Case Intake**:
   - typed notes
   - dictated transcript text
   - photos or scans
   - audio files
   - PDFs, text files, and CSV files

2. Organize the cases automatically:
   - age, sex, diagnosis, treatment, outcome, and missing items are extracted from typed/OCR text
   - similar cases are grouped by diagnosis and treatment pattern
   - adaptive CRF fields are suggested when repeated patterns appear

3. Use **Academic AI Review**:
   - local rules are used by default
   - OpenAI can be enabled only after study privacy approval
   - image/audio interpretation is off unless multimodal AI is explicitly enabled
   - every AI review is audited

4. Use **Academic CV**:
   - review publication opportunities
   - store academic outputs such as publication ideas, abstract drafts, manuscript drafts, conference submissions, posters, audit projects, teaching sessions, grant proposals, and CV-linked items
   - create CV items for abstracts, posters, presentations, audits, datasets, protocols, grants, awards, or manuscripts
   - link a CV item to a captured case
   - export an academic portfolio as Markdown or a CV tracker as CSV

## Safe Workflow

1. Enter cases in **Case Intake**.
2. Remove names, phone numbers, hospital numbers, exact addresses, and unnecessary dates.
3. Run Academic AI review only after de-identification.
4. Open **Academic CV**.
5. Review publication opportunities.
6. Add an Academic Output when an idea becomes a planned abstract, poster, audit, grant, teaching session, or manuscript.
7. Add a CV item only when it represents a real output you want in your CV tracker.
8. Export the Markdown portfolio before meetings, appraisals, or manuscript planning.

## AI Helpers

The Academic Workbench includes safe local helpers:

- de-identification preview
- case note to structured summary
- missing-field check
- inconsistency check
- publication idea suggestions
- CV item suggestion

External AI is off by default. If enabled later, obvious identifiers are blocked unless `CDS_AI_ALLOW_PHI=true` is explicitly configured. Every AI request is audited.

## Important Limits

- This is not a replacement for ethics approval, consent review, or supervisor review.
- AI suggestions are drafts and must be checked against source records.
- AI must not claim novelty. Use suggested search terms for a manual literature review.
- Do not send PHI to external AI unless your study and institution explicitly allow it.
