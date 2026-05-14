# Android Capacitor Wrapper

Use this only after the PWA works well in Android Chrome.

The Android app should be a secure shell around the hosted Clinical Data Studio website. Do not put the clinical database inside the Android app.

## What This Gives You

- A normal Android APK that opens your hosted app.
- The same login, roles, audit trail, and PostgreSQL database.
- One codebase to maintain.

## What This Does Not Do

- It does not create a second backend.
- It does not store study data inside the phone app.
- It does not replace HTTPS, backups, user roles, or audit review.

## Before You Start

Confirm:

1. The Lightsail or central server URL works on Android Chrome.
2. You can install the PWA from Chrome.
3. Offline CRF drafts work and sync.
4. HTTPS is active.
5. Users log in with named accounts.

## Build Steps Later

Install Node.js on a development computer, then run:

```bash
npm install
npx cap init "Clinical Data Studio" "org.kundakarlabp.clinicaldatastudio" --web-dir=static
npx cap add android
npx cap sync android
npx cap open android
```

For production, configure the Android shell to open:

```text
https://your-domain.example
```

Then build a debug APK from Android Studio.

## Important Warnings

- Play Store release needs app signing, privacy policy, and Google Play data safety forms.
- If patient data is used, confirm institutional approval before distributing APKs.
- Keep the app pointed to the server URL. Do not copy the database into Android.

