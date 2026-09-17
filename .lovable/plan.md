# Merge the supplied Vulnera Zen source

## Goal
Make the current SBOM platform match the uploaded ZIP while keeping its live data, secure sign-in, and managed backend intact.

## Changes
- Replace the current application screens, shared UI, styles, parsing, reporting, and intelligence logic with the supplied versions where they differ.
- Add source files and public assets that exist only in the ZIP.
- Preserve generated backend connection files, local secrets, project identity, and current database records.
- Reconcile package requirements and database migrations instead of blindly overwriting managed configuration.
- Fix the sign-in hydration mismatch while retaining the supplied sign-in experience.

## Verification
- Confirm every supplied route is available and page metadata remains complete.
- Check sign-in, dashboard, datasets, SBOM upload, vulnerability intelligence, licenses, and reports.
- Verify desktop and mobile rendering, console errors, and representative interactions.

## Technical details
The ZIP is a TanStack Start application matching the current architecture. The merge will use its newer feature files directly, but generated Lovable Cloud clients and environment files remain controlled by this project. Existing records are not replaced because the archive contains schema migrations but no data export.
