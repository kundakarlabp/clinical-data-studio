# CRF Builder Guide

Clinical Data Studio lets an admin build REDCap-like CRFs without coding.

## Field Types

Use these common field types:

- text
- textarea
- integer
- decimal
- date
- datetime
- dropdown/select
- radio
- checkbox
- yes/no
- file upload
- calculated field
- section header or descriptive text

## Coded Choices

For analyzable fields, use coded value-label choices:

```text
1, Male
2, Female
3, Other
```

The saved data stores the coded value. The screen shows the label. Exports can use raw values, labels, or both.

## Field Metadata

For each field, review:

- variable name
- label
- help text or field note
- units
- required flag
- validation type
- minimum and maximum
- regex validation if needed
- PHI-sensitive flag
- identifier flag

Use short stable variable names. Do not rename a field after real data entry unless you intentionally create a new CRF version.

## Branching Logic

Use simple show-if rules:

```text
sex == 2
age >= 18 AND pregnant == 1
diagnosis IN ["TB", "HIV"]
```

Keep logic simple. Preview the CRF as a data-entry user before publishing.

## Calculated Fields

Calculated fields should be transparent and checked before real use. Supported presets include BMI, age from date of birth, days between dates, antibiotic duration, simple score sum, qSOFA-style score, and eGFR placeholder logic. For clinical formulas, verify against your protocol and statistical plan before using in analysis.

## Versioning

Every saved entry stores:

- CRF version
- schema snapshot
- field labels and choices at the time of entry
- validation and branching metadata
- entry hash

This protects old records when the CRF later changes. Exports warn when older form versions are present.

## Data Dictionary

Use **Dictionary** to export or import a CRF CSV data dictionary. Include:

- field name
- field label
- field type
- choices
- required flag
- validation
- branching logic
- units
- notes

After import, preview the CRF and enter a test participant before using it for real study data.

## Draft, Publish, Retire, Lock

Use the CRF lifecycle controls before real data entry:

- **Draft**: build and edit the form; data entry is blocked.
- **Validate**: checks field names, labels, coded choices, branching/calculation references, and file-upload rules.
- **Publish**: makes the CRF available for data entry.
- **Retire**: keeps old data readable but blocks new entries.
- **Lock**: freezes the CRF structure from further data entry until unlocked by an admin/reviewer.

Old entries keep their form version and schema snapshot, so later CRF edits do not remove old variables from exports.
