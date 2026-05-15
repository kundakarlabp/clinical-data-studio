# Android PWA Setup

Clinical Data Studio should first be used on Android as an installable web app.

## Admin Steps

1. Run the app on the central study computer or Lightsail server.
2. Open the app URL in Android Chrome.
3. Log in with a named user account.
4. Tap **Install App** if the button appears.
5. If the button does not appear, open Chrome menu and tap **Add to Home screen**.
6. Open the new Clinical Data Studio icon from the Android home screen.

## Data Entry Use

- Use **Data Entry** for CRFs.
- Use **Case Intake** for photos, PDFs, audio, and unstructured notes.
- Use **Local Drafts** to review CRF drafts saved on that phone.
- Sync drafts before clearing browser data or switching phones.

## Offline Drafts And Conflicts

When the phone loses connection, CRF edits are saved as local IndexedDB drafts on that phone. They are not in the central study database until synced.

Before syncing, the app checks whether the server record changed after the draft started. If another user changed the record, the app marks the draft as a conflict instead of silently overwriting data.

Use **Local Drafts** to review:

- pending drafts
- synced drafts
- errors
- conflicts

For conflicts, compare the phone draft with the server version and decide whether to keep the server record, keep the local draft, or manually merge.

## Important Safety Notes

- Do not share the admin account.
- Each person should have a named account.
- Offline drafts stay on that phone until synced.
- The phone app shell does not store the main clinical database.
- If the server is offline, clinical data cannot sync until the server is reachable again.
- Do not uninstall Chrome or clear site data before syncing drafts.
