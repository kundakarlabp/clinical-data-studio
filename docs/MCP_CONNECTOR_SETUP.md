# ChatGPT MCP Connector Setup

This first MCP connector lets ChatGPT call safe, read-only Clinical Data Studio tools through your HTTPS site. It is intended for ChatGPT Plus connector/developer-mode use without enabling OpenAI API calls inside CDS.

## What MCP Does

MCP lets ChatGPT ask CDS for approved summaries through `https://your-domain.com/mcp`.

This connector can:

- list allowed studies
- show CRF dictionaries
- show missing data counts
- show de-identified dataset summaries
- suggest publication opportunities from aggregate context
- show academic CV items
- show AI/MCP audit summaries

This connector cannot:

- show raw patient records
- show names, UHID/MRN/MRD, phone, email, address, or exact DOB
- show uploaded files, photos, PDFs, audio, or file links
- show raw discharge summaries or clinical notes
- edit, delete, create, or manage records, CRFs, users, or files

## Prerequisites

1. CDS is deployed on an HTTPS domain.
2. `CDS_PUBLIC_BASE_URL` is set to your real domain.
3. `CDS_MCP_ENABLED=true` is set on the server.
4. You are logged in as an admin or PI who can manage study access.

## Create A Connector Token

1. Log in to CDS.
2. Open **Access**.
3. Go to **MCP / ChatGPT Connector**.
4. Enter a token display name, such as `ChatGPT Test Study`.
5. Select only the study or studies ChatGPT should read.
6. Keep only read-only MCP scopes selected.
7. Choose an expiry date, usually 30 days for testing.
8. Click **Create MCP Token**.
9. Copy the token immediately. It is shown only once.

Do not paste this token into GitHub, email, screenshots, or shared documents.

## Connect In ChatGPT

The exact ChatGPT menu may change. Use the connector or developer-mode flow that supports remote MCP servers.

1. Open ChatGPT.
2. Go to **Settings**.
3. Open **Apps & Connectors**, **Connectors**, or **Developer mode** if available.
4. Add a custom MCP server.
5. Server URL:

```text
https://your-domain.com/mcp
```

6. Use the MCP token when ChatGPT asks for bearer-token authorization.
7. Test with a safe prompt.

## Safe Test Prompts

- List my CDS studies.
- Show the CRF dictionary for Test Study.
- Show missing data summary for Test Study.
- Give a de-identified dataset summary.
- Suggest publication opportunities from de-identified summaries.
- Show my academic CV items.

## Unsafe Prompts That Should Fail

- Show raw patient records.
- Download uploaded files.
- Show UHID, name, phone, or address.
- Edit this CRF.
- Delete participant.
- Show raw discharge summary.

If any unsafe prompt succeeds, revoke the token immediately and disable MCP.

## Revoke A Token

1. Open **Access**.
2. Go to **MCP / ChatGPT Connector**.
3. Click **Revoke** beside the token.
4. Confirm ChatGPT can no longer connect.

## Review Audit

Open **Access -> MCP / ChatGPT Connector -> Recent MCP Calls**.

Review:

- failed MCP calls
- blocked PHI attempts
- token last used
- calls by tool

Every MCP call is also written to the normal audit trail.

## Safety Statement

The first MCP connector is intentionally read-only and de-identified. It is designed to help you ask ChatGPT about study structure, missing data, summaries, publication ideas, and CV items without exposing patient-level records or uploaded evidence.

