# Validation Execution Record

Study or deployment:

Tester:

Date:

App version or Git commit:

Database file:

## Required Evidence

- Screenshot of First Run Setup completion or admin access review.
- Screenshot of user roles and data access groups.
- Data dictionary import test result.
- Manual CRF entry test result.
- Public survey submission test result when surveys are used.
- E-consent signature record review when consent is used.
- File upload field test when file fields are used.
- Query open, response, and close test.
- Field verification or freeze test.
- CSV export and codebook export files.
- Backup creation, encrypted archive creation, and restore drill result.
- Audit trail review sign-off.

## Test Result Log

| Test | Expected Result | Actual Result | Pass/Fail | Evidence Location |
| --- | --- | --- | --- | --- |
| First-run setup | Permanent admin password created | | | |
| Login lockout | Repeated failed attempts temporarily lock account | | | |
| CRF build/edit | Version history retained | | | |
| Data entry | Server validation blocks invalid data | | | |
| Public survey | Token link creates participant entry | | | |
| E-consent | Signature metadata retained | | | |
| File field | File metadata and content retained | | | |
| Record import | CSV creates/updates expected entries | | | |
| Export | CSV/codebook opens correctly | | | |
| Backup restore | Restored database contains expected records | | | |

## Sign-Off

Validated by:

Approved for use by:

Limitations or deviations:
