# User Roles And Permissions

Use named accounts. Do not share passwords.

## Roles

| Role | Intended user | Main permissions |
| --- | --- | --- |
| `super_admin` | System owner | All studies, all users, deployment status |
| `project_admin` | Study PI/admin | Manage assigned study, forms, users, exports |
| `pi` | Principal investigator | Same project permissions as project admin |
| `data_entry` | Data entry staff | Create and update unlocked CRFs in assigned study/group |
| `reviewer` | Monitor/reviewer | Queries, review, lock/freeze, audit view |
| `analyst` | Statistician/analyst | Analysis and de-identified export, no record editing |
| `viewer` | Read-only collaborator | View assigned study analysis only |

Legacy roles `admin`, `owner`, and `read_only` are still accepted for older local databases.

## Add A User

1. Log in as `super_admin`.
2. Open Access.
3. Create a user with a temporary password.
4. Assign the user to a study.
5. Choose project role.
6. Choose data access group if needed.

## Reset A Password

Use the admin dashboard or API:

```bash
curl -X POST https://your-domain.example/api/admin/users/USER_ID/reset-password \
  -H "Authorization: Bearer YOUR_ADMIN_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"NewTemporaryPassword123"}'
```

The user must change the password after login.

## Data Access Groups

Use data groups when different sites should see only their own participants. Assign the data entry user to the correct data group in Access.
