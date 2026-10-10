# Katsina NYSC Operations Suite — Phase 1 Starter

Separate state-level application for Central Registry and Secretariat file tracking. It does not modify KATZIMS or reuse its database.

## Architecture
- `frontend/`: static HTML/CSS/JavaScript frontend, deployable to Netlify.
- `backend/`: Flask REST API, deployable as a separate Render web service.
- PostgreSQL: create a **new** database for this application; never point it at the KATZIMS database.
- KATZIMS integration is intentionally not enabled in Phase 1.

## Features in this starter
- First-admin bootstrap protected by `SETUP_KEY`.
- Role-based access: State Coordinator Admin, Central Registry, Branch Head, Registry Officer, Read-only Auditor.
- Branch/account management.
- File registration and State Code search.
- File issue/dispatch, receipt acknowledgement, return, and movement history.
- Dashboard totals: collected today, returned in selected period, currently circulating, overdue, and unacknowledged dispatches.
- Date and location filters.
- Audit log for key actions.

## Deploy backend to Render
1. Create a **new** Git repository from this folder, or push this folder to a new repository.
2. Create a new Render PostgreSQL database. Keep it separate from KATZIMS.
3. Create a new Render Web Service pointing at `backend/` as the root directory.
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Set environment variables:
   - `DATABASE_URL` = new Operations Suite PostgreSQL internal URL
   - `SECRET_KEY` = long random secret
   - `SETUP_KEY` = long one-time setup secret
   - `FRONTEND_ORIGIN` = Netlify site URL, e.g. `https://your-site.netlify.app`
   - `TIMEZONE` = `Africa/Lagos`
7. Deploy and use `POST /api/setup/admin` once to create the first admin. Example JSON: `{"setup_key":"YOUR_SETUP_KEY","full_name":"State Coordinator Admin","username":"stateadmin","password":"USE-A-LONG-UNIQUE-PASSWORD"}`. Use the endpoint only once; it locks after the first account is created.

## Deploy frontend to Netlify
1. Create a separate Netlify site from the `frontend/` folder.
2. Set environment/build config is not needed for this plain static starter. Open `frontend/config.js` and set `API_BASE_URL` to the Render API base URL (e.g. `https://your-api.onrender.com`).
3. Redeploy after changing `config.js`.

## Important before real use
- This is a Phase 1 starter and must be tested with test records before operational use.
- Configure HTTPS, strong unique secrets, backups, and an access review before real data is entered.
- Do not upload confidential file attachments until a private object-storage design and malware scanning policy are selected.
- `State Code` is a search key only; files are uniquely identified by the system-generated file reference.
- The dashboard is live from database queries on refresh. WebSocket/push updates can be added after the core workflow is approved.
- The backend applies server-side role checks. Hiding a frontend menu is not treated as security.
- No KATZIMS database credentials or direct cross-database access are required for Phase 1.
