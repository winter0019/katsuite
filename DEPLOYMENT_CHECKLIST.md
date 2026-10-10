# Deployment and safety checklist

## Before deploying
- [ ] Create a new repository for this project; do not overwrite the KATZIMS repository.
- [ ] Create a separate PostgreSQL database for the Operations Suite.
- [ ] Confirm the new database URL is not the KATZIMS `DATABASE_URL`.
- [ ] Set `SECRET_KEY`, `SETUP_KEY`, `DATABASE_URL`, and `FRONTEND_ORIGIN` as Render environment variables.
- [ ] Set `frontend/config.js` to the new API URL.
- [ ] Confirm the Netlify domain is included in `FRONTEND_ORIGIN`.
- [ ] Deploy backend, test `/api/health`, then deploy frontend.
- [ ] Bootstrap the first administrator once; then rotate/remove `SETUP_KEY`.
- [ ] Create branch accounts with temporary unique passwords and deliver them securely.
- [ ] Test with fictitious files before entering official records.
- [ ] Verify database backups and restore procedure.

## Acceptance tests
- [ ] Admin can create and deactivate accounts and add branches.
- [ ] Registry officer can register a file with a unique reference.
- [ ] Search works by reference, title, subject, State Code and holder.
- [ ] Dispatch creates an unacknowledged delivery.
- [ ] Recipient acknowledgement changes status to In Circulation.
- [ ] Due date past and still circulating marks file Overdue.
- [ ] Return is recorded with time, location and receiving officer.
- [ ] Audit trail records privileged operations.
- [ ] Non-admin cannot manage accounts or inspect admin-only audit data.
- [ ] No requests are made to the KATZIMS database.

## Known Phase 1 boundaries
- No file attachment storage yet.
- No live push updates; dashboard refreshes by request.
- No KATZIMS integration yet.
- Branch-head action scoping needs to be tightened to the exact assigned branch before broad production use.
- Dashboard date/location filters and PDF report exports are planned follow-up improvements; the File Register and Movement Report already support date filters.
