import os, secrets, hashlib, hmac
from datetime import datetime, date, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import psycopg
from psycopg.rows import dict_row

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '')
FRONTEND_ORIGIN = os.environ.get('FRONTEND_ORIGIN', '*')
CORS(app, resources={r"/api/*": {"origins": [x.strip() for x in FRONTEND_ORIGIN.split(',') if x.strip()] or ['*']}})

ROLES = {'State Coordinator Admin', 'Central Registry', 'Branch Head', 'Registry Officer', 'Zonal Inspector', 'Local Government Inspector', 'Read-only Auditor'}
ADMIN_ROLES = {'State Coordinator Admin'}
REGISTRY_ROLES = {'State Coordinator Admin', 'Central Registry', 'Registry Officer'}
ALL_READ_ROLES = ROLES


def db():
    url = os.environ.get('DATABASE_URL')
    if not url:
        raise RuntimeError('DATABASE_URL is not configured. Set it to the new Operations Suite PostgreSQL database.')
    return psycopg.connect(url, row_factory=dict_row, connect_timeout=10)


def pw_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310000).hex()
    return f'{salt}${digest}'


def pw_ok(password, stored):
    try:
        salt, digest = stored.split('$', 1)
        check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 310000).hex()
        return hmac.compare_digest(check, digest)
    except Exception:
        return False


def init_db():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY, full_name TEXT NOT NULL, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL, branch_id BIGINT,
            active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now())''')
        conn.execute('''CREATE TABLE IF NOT EXISTS branches (
            id BIGSERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, branch_type TEXT NOT NULL DEFAULT 'Secretariat Branch',
            location TEXT NOT NULL DEFAULT '', active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now())''')
        conn.execute('''CREATE TABLE IF NOT EXISTS files (
            id BIGSERIAL PRIMARY KEY, reference_no TEXT UNIQUE NOT NULL, title TEXT NOT NULL,
            subject TEXT NOT NULL DEFAULT '', state_code TEXT NOT NULL DEFAULT '', originating_office TEXT NOT NULL,
            current_location TEXT NOT NULL, current_holder TEXT NOT NULL DEFAULT '', registered_by BIGINT REFERENCES users(id),
            registered_at TIMESTAMPTZ NOT NULL DEFAULT now(), due_at TIMESTAMPTZ,
            status TEXT NOT NULL DEFAULT 'At Registry', archived BOOLEAN NOT NULL DEFAULT FALSE,
            notes TEXT NOT NULL DEFAULT '')''')
        conn.execute('''CREATE TABLE IF NOT EXISTS movements (
            id BIGSERIAL PRIMARY KEY, file_id BIGINT NOT NULL REFERENCES files(id), action TEXT NOT NULL,
            from_location TEXT NOT NULL DEFAULT '', to_location TEXT NOT NULL DEFAULT '', sender TEXT NOT NULL DEFAULT '',
            recipient TEXT NOT NULL DEFAULT '', dispatched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            acknowledged_at TIMESTAMPTZ, due_at TIMESTAMPTZ, returned_at TIMESTAMPTZ,
            remarks TEXT NOT NULL DEFAULT '', created_by BIGINT REFERENCES users(id))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
            id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id), action TEXT NOT NULL,
            entity_type TEXT NOT NULL, entity_id TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now())''')
        
        for name, kind, loc in [
            ('State Coordinator Office','State Office','Katsina State Secretariat'),
            ('Central Registry','Registry','Katsina State Secretariat'),
            ('CIM','Secretariat Branch','Katsina State Secretariat'),
            ('CW&HS','Secretariat Branch','Katsina State Secretariat'),
            ('CDS','Secretariat Branch','Katsina State Secretariat'),
            ('Other Secretariat Branch/Unit','Secretariat Branch','Katsina State Secretariat')]:
            conn.execute('INSERT INTO branches(name, branch_type, location) VALUES (%s,%s,%s) ON CONFLICT(name) DO NOTHING', (name,kind,loc))
        
        zone_lgis = {
            'Katsina Zone': ['Katsina A','Katsina B','Batagarawa','Rimi','Charanchi','Kaita','Jibia'],
            'Daura Zone': ['Daura','Baure','Mani','Mashi','Dutsi','Bindawa','Zango','Sandamu','Maiadua'],
            'Funtua Zone': ['Funtua','Malumfashi','Bakori','Danja'],
            'Dutsin-Ma Zone': ['Dutsin-Ma','Ingawa','Kusada','Kankia']
        }
        for zone, lgis in zone_lgis.items():
            conn.execute('INSERT INTO branches(name,branch_type,location) VALUES (%s,%s,%s) ON CONFLICT(name) DO NOTHING', (zone,'Zonal Office',zone))
            for lgi in lgis:
                conn.execute('INSERT INTO branches(name,branch_type,location) VALUES (%s,%s,%s) ON CONFLICT(name) DO NOTHING', (lgi,'LGA Office',zone))


def audit(action, entity_type, entity_id='', details=''):
    user_id = getattr(g, 'user', {}).get('id') if getattr(g, 'user', None) else None
    with db() as conn:
        conn.execute('INSERT INTO audit_logs(user_id,action,entity_type,entity_id,details) VALUES(%s,%s,%s,%s,%s)',
                     (user_id, action, entity_type, str(entity_id), details[:2000]))


def token_for(user):
    import json, base64
    payload = {'uid': user['id'], 'exp': int((datetime.now(timezone.utc)+timedelta(hours=8)).timestamp()), 'nonce': secrets.token_hex(8)}
    raw = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).decode().rstrip('=')
    sig = hmac.new(app.config['SECRET_KEY'].encode(), raw.encode(), hashlib.sha256).hexdigest()
    return raw + '.' + sig


def decode_token(token):
    import json, base64
    try:
        raw, sig = token.split('.',1)
        expected = hmac.new(app.config['SECRET_KEY'].encode(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): return None
        payload = json.loads(base64.urlsafe_b64decode(raw + '='*((4-len(raw)%4)%4)))
        if payload['exp'] < int(datetime.now(timezone.utc).timestamp()): return None
        with db() as conn:
            return conn.execute('SELECT u.id,u.full_name,u.username,u.role,u.branch_id,u.active,b.name AS branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id WHERE u.id=%s', (payload['uid'],)).fetchone()
    except Exception:
        return None


def require_roles(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            header = request.headers.get('Authorization','')
            if not header.startswith('Bearer '): return jsonify(error='Authentication required.'), 401
            user = decode_token(header[7:])
            if not user or not user['active']: return jsonify(error='Session expired or account disabled.'), 401
            if roles and user['role'] not in roles: return jsonify(error='You do not have permission for this action.'), 403
            g.user = user
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def office_scope_sql(user, alias='f'):
    """Limit each office to files currently in its custody; Registry retains global tracking."""
    role = user['role']
    office = (user.get('branch_name') or '').strip()

    # Central Registry is the system-wide registry and can track all registered files.
    if role == 'Central Registry' or (role == 'Registry Officer' and office == 'Central Registry'):
        return 'TRUE', []

    # The State Coordinator register contains only files currently submitted to that office.
    if role == 'State Coordinator Admin':
        return f"{alias}.current_location=%s", ['State Coordinator Office']

    # LGIs see files currently held by their assigned LGA office.
    if role == 'Local Government Inspector':
        if not office:
            return 'FALSE', []
        # LGI may see files physically held by the office, plus files specifically
        # dispatched to this office that are still awaiting physical acknowledgement.
        return (f"({alias}.current_location=%s OR EXISTS (SELECT 1 FROM movements lgi_m WHERE lgi_m.file_id={alias}.id AND lgi_m.action='DISPATCHED' AND lgi_m.to_location=%s AND lgi_m.acknowledged_at IS NULL AND lgi_m.returned_at IS NULL))", [office, office])

    # Branches see files currently held by their assigned branch/unit.
    if role == 'Branch Head':
        if not office:
            return 'FALSE', []
        return f"{alias}.current_location=%s", [office]

    # ZIs see files currently held by their assigned zonal office.
    if role == 'Zonal Inspector':
        if not office:
            return 'FALSE', []
        return f"{alias}.current_location=%s", [office]

    # Other registry officers are limited to their assigned office unless central registry.
    if role == 'Registry Officer':
        if not office:
            return 'FALSE', []
        return f"{alias}.current_location=%s", [office]

    return 'FALSE', []


def user_can_access_file(conn, user, file_id):
    clause, params = office_scope_sql(user)
    return bool(conn.execute(f'SELECT 1 FROM files f WHERE f.id=%s AND {clause}', [file_id, *params]).fetchone())


def is_central_registry(user):
    return user['role'] == 'Central Registry' or (user['role'] == 'Registry Officer' and user.get('branch_name') == 'Central Registry')

def bad(message, code=400): return jsonify(error=message), code

def get_json(): return request.get_json(silent=True) or {}

@app.before_request
def boot():
    if request.path.startswith('/api/') and request.path != '/api/health':
        try: init_db()
        except Exception as exc: app.logger.exception('Database initialization failed')

@app.get('/api/health')
def health():
    try:
        with db() as conn: conn.execute('SELECT 1')
        return jsonify(status='ok', service='Katsina NYSC Operations Suite API', database='connected')
    except Exception as exc:
        app.logger.error('Health check database error: %s', exc)
        return jsonify(status='degraded', service='Katsina NYSC Operations Suite API', error='Database unavailable or not configured.'), 503

@app.post('/api/auth/login')
def login():
    data = get_json()
    if not data.get('username') or not data.get('password'): return bad('Username and password are required.')
    with db() as conn:
        user = conn.execute('SELECT u.*,b.name AS branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id WHERE lower(u.username)=lower(%s)', (str(data['username']).strip(),)).fetchone()
    if not user or not user['active'] or not pw_ok(str(data['password']), user['password_hash']): return bad('Invalid username or password.', 401)
    token = token_for(user)
    audit('login','user',user['id'],'Successful login')
    return jsonify(token=token, user={'id':user['id'],'full_name':user['full_name'],'username':user['username'],'role':user['role'],'branch_id':user['branch_id'],'branch_name':user['branch_name']})

@app.get('/api/me')
@require_roles(*ALL_READ_ROLES)
def me():
    u=g.user
    return jsonify(user={'id':u['id'],'full_name':u['full_name'],'username':u['username'],'role':u['role'],'branch_id':u['branch_id'],'branch_name':u['branch_name']})

@app.get('/api/branches')
@require_roles(*ALL_READ_ROLES)
def branches_list():
    with db() as conn: rows=conn.execute('SELECT id,name,branch_type,location,active FROM branches ORDER BY name').fetchall()
    return jsonify(branches=rows)

# --- Rule 2: Only Central Registry / Registry Officers can register files collected from offices ---
@app.post('/api/files')
@require_roles('Central Registry', 'Registry Officer', 'State Coordinator Admin')
def file_create():
    if not is_central_registry(g.user) and g.user['role'] != 'State Coordinator Admin': 
        return bad('Only Central Registry is authorized to register files collected from offices.', 403)
    
    d = get_json()
    if not d.get('title') or not d.get('originating_office') or not d.get('state_code'): 
        return bad('File title, originating office, and Corps Member state code are required.')
    
    with db() as conn:
        seq = conn.execute("SELECT nextval(pg_get_serial_sequence('files','id')) AS n").fetchone()['n']
        ref = f"KNS-FM-{datetime.now().year}-{seq:06d}"
        
        # Rule 3: Record based on the corps member state code
        row = conn.execute('''INSERT INTO files(id,reference_no,title,subject,state_code,originating_office,current_location,current_holder,registered_by,due_at,notes,status)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''', 
            (seq, ref, d['title'].strip(), d.get('subject','').strip(), d['state_code'].strip().upper(), 
             d['originating_office'].strip(), 'Central Registry', g.user['full_name'], g.user['id'], 
             d.get('due_at') or None, d.get('notes','').strip(), 'At Registry')).fetchone()
        
        conn.execute("INSERT INTO movements(file_id,action,from_location,to_location,sender,recipient,acknowledged_at,created_by,remarks) VALUES(%s,'REGISTERED','',%s,%s,%s,now(),%s,%s)", 
                     (seq, 'Central Registry', d['originating_office'], g.user['full_name'], g.user['id'], 'File collected and registered based on corps member state code'))

    audit('register', 'file', row['id'], ref)
    return jsonify(file=row), 201


@app.get('/api/files')
@require_roles(*ALL_READ_ROLES)
def files_list():
    q = (request.args.get('q') or '').strip()
    loc = (request.args.get('location') or '').strip()
    status = (request.args.get('status') or '').strip()
    start = (request.args.get('start') or '').strip()
    end = (request.args.get('end') or '').strip()
    
    scope, scope_args = office_scope_sql(g.user, 'f')
    sql = '''SELECT f.*, CASE WHEN f.status='In Circulation' AND f.due_at IS NOT NULL AND f.due_at < now() THEN 'Overdue' ELSE f.status END AS computed_status FROM files f WHERE f.archived=FALSE AND ''' + scope
    args = list(scope_args)
    
    if q:
        sql += " AND (f.reference_no ILIKE %s OR f.title ILIKE %s OR f.subject ILIKE %s OR f.state_code ILIKE %s OR f.current_holder ILIKE %s)"
        args += [f'%{q}%']*5
    if loc and loc != 'All locations': 
        sql += ' AND f.current_location=%s'
        args.append(loc)
    if start: 
        sql += ' AND f.registered_at >= %s::date'
        args.append(start)
    if end: 
        sql += " AND f.registered_at < (%s::date + interval '1 day')"
        args.append(end)
    if status: 
        sql += " AND (CASE WHEN f.status='In Circulation' AND f.due_at IS NOT NULL AND f.due_at < now() THEN 'Overdue' ELSE f.status END)=%s"
        args.append(status)
        
    sql += ' ORDER BY f.registered_at DESC LIMIT 500'
    with db() as conn: 
        rows = conn.execute(sql, args).fetchall()
    return jsonify(files=rows)


@app.get('/api/files/<int:file_id>')
@require_roles(*ALL_READ_ROLES)
def file_detail(file_id):
    with db() as conn:
        f = conn.execute("SELECT f.*, CASE WHEN f.status='In Circulation' AND f.due_at IS NOT NULL AND f.due_at < now() THEN 'Overdue' ELSE f.status END AS computed_status FROM files f WHERE f.id=%s",(file_id,)).fetchone()
        if not f or not user_can_access_file(conn, g.user, file_id): return bad('File not found or access denied.',404)
        moves = conn.execute('SELECT * FROM movements WHERE file_id=%s ORDER BY dispatched_at DESC,id DESC',(file_id,)).fetchall()
    return jsonify(file=f, movements=moves)


# --- Rule 6: Other offices search corps member files using state code and forward appropriately ---
@app.post('/api/files/<int:file_id>/forward')
@require_roles('Local Government Inspector', 'Branch Head', 'Registry Officer', 'State Coordinator Admin', 'Zonal Inspector')
def forward_file(file_id):
    u = g.user
    # LGIs are explicitly blocked from submitting or forwarding files (Rule 8)
    if u['role'] == 'Local Government Inspector':
        return bad('Local Government Inspectors have view and search only rights and cannot forward files.', 403)
        
    d = get_json()
    if not d.get('to_location'): 
        return bad('Target office/location is required.')
        
    with db() as conn:
        f = conn.execute('SELECT * FROM files WHERE id=%s AND archived=FALSE FOR UPDATE', (file_id,)).fetchone()
        if not f: return bad('File not found.', 404)
        
        current_loc = f['current_location']
        target = d['to_location'].strip()
        recipient = d.get('recipient', '').strip() or 'Office Registry'
        due = d.get('due_at') or None
        
        conn.execute('''INSERT INTO movements(file_id, action, from_location, to_location, sender, recipient, due_at, remarks, created_by)
            VALUES(%s, 'FORWARDED', %s, %s, %s, %s, %s, %s, %s)''', 
            (file_id, current_loc, target, u['full_name'], recipient, due, d.get('remarks', ''), u['id']))
            
        conn.execute("UPDATE files SET current_location=%s, current_holder=%s, status='In Circulation', due_at=%s WHERE id=%s", 
                     (target, recipient, due, file_id))

    audit('forward', 'file', file_id, f"forwarded from {current_loc} to {target}")
    return jsonify(message='File forwarded successfully.')


# --- Rule 4 & 5: Central Registry Dashboard & Full Circulation Tracking ---
@app.get('/api/registry/dashboard')
@require_roles('Central Registry', 'Registry Officer', 'State Coordinator Admin')
def registry_dashboard():
    # The State Coordinator must not inherit the Registry's system-wide circulation view.
    # Their dashboard is limited to files physically at the State Coordinator Office.
    is_state_coordinator = g.user['role'] == 'State Coordinator Admin'
    with db() as conn:
        if is_state_coordinator:
            scope = "current_location=%s"
            params = ['State Coordinator Office']
            stats = conn.execute('''SELECT
                count(*) AS total_collected,
                count(*) FILTER (WHERE status='Returned') AS returned_files,
                count(*) FILTER (WHERE status='In Circulation') AS acknowledged_files,
                count(*) FILTER (WHERE status='In Circulation' AND due_at < now()) AS overdue_files
                FROM files WHERE archived=FALSE AND current_location=%s''', params).fetchone()
            circulation = conn.execute('''SELECT id, reference_no, title, state_code, current_location, current_holder, status, due_at
                FROM files WHERE archived=FALSE AND status != 'Archived' AND current_location=%s ORDER BY id DESC''', params).fetchall()
        else:
            stats = conn.execute('''SELECT
                count(*) AS total_collected,
                count(*) FILTER (WHERE status='Returned') AS returned_files,
                count(*) FILTER (WHERE status='In Circulation') AS acknowledged_files,
                count(*) FILTER (WHERE status='In Circulation' AND due_at < now()) AS overdue_files
                FROM files WHERE archived=FALSE''').fetchone()
            circulation = conn.execute('''SELECT id, reference_no, title, state_code, current_location, current_holder, status, due_at
                FROM files WHERE archived=FALSE AND status != 'Archived' ORDER BY id DESC''').fetchall()
    return jsonify(stats=stats, circulation=circulation)


# --- Rule 7: State Coordinator Office Metrics ---
@app.get('/api/state-coordinator/dashboard')
@require_roles('State Coordinator Admin', 'Zonal Inspector')
def state_coordinator_dashboard():
    # State Coordinator metrics are restricted to files whose current physical location
    # is the State Coordinator Office. A file sent to CIM or another branch is excluded.
    if g.user['role'] == 'State Coordinator Admin':
        location_clause = "current_location=%s"
        params = ['State Coordinator Office']
    else:
        office = (g.user.get('branch_name') or '').strip()
        if not office:
            return jsonify(metrics={'total_received': 0, 'treated_files': 0, 'untreated_files': 0, 'returned_files': 0, 'put_away_files': 0})
        location_clause = "current_location=%s"
        params = [office]
    with db() as conn:
        metrics = conn.execute('''SELECT
            count(*) AS total_received,
            count(*) FILTER (WHERE status='Treated' OR status='In Circulation') AS treated_files,
            count(*) FILTER (WHERE status='At Registry' OR status='In Transit') AS untreated_files,
            count(*) FILTER (WHERE status='Returned') AS returned_files,
            count(*) FILTER (WHERE status='Put Away' OR status='Archived') AS put_away_files
            FROM files WHERE archived=FALSE AND ''' + location_clause, params).fetchone()
    return jsonify(metrics=metrics)


@app.get('/api/dashboard')
@require_roles(*ALL_READ_ROLES)
def dashboard():
    user = g.user
    scope, scope_args = office_scope_sql(user, 'f')
    office = (user.get('branch_name') or '').strip()
    is_lgi = user['role'] == 'Local Government Inspector'
    with db() as conn:
        counts = conn.execute("""SELECT
          count(*) AS total_files,
          count(*) FILTER (WHERE f.registered_at::date=current_date) AS registered_today,
          count(*) FILTER (WHERE f.status='Returned' AND f.id IN (SELECT file_id FROM movements WHERE action='RETURNED' AND returned_at::date=current_date)) AS returned_today,
          count(*) FILTER (WHERE f.status='In Circulation') AS circulating,
          count(*) FILTER (WHERE f.status='In Transit') AS in_transit,
          count(*) FILTER (WHERE f.status='In Circulation' AND f.due_at < now()) AS overdue
          FROM files f WHERE f.archived=FALSE AND """+scope, scope_args).fetchone()
        if is_lgi:
            collected = conn.execute("SELECT count(DISTINCT m.file_id) AS n FROM movements m WHERE m.action='DISPATCHED' AND m.to_location=%s AND m.acknowledged_at::date=current_date", (office,)).fetchone()['n']
            unack = conn.execute("SELECT count(DISTINCT m.file_id) AS n FROM movements m JOIN files f ON f.id=m.file_id WHERE m.action='DISPATCHED' AND m.to_location=%s AND m.acknowledged_at IS NULL AND m.returned_at IS NULL AND f.archived=FALSE", (office,)).fetchone()['n']
        else:
            collected = counts['registered_today']
            unack = conn.execute("SELECT count(*) AS n FROM movements m JOIN files f ON f.id=m.file_id WHERE m.action='DISPATCHED' AND m.acknowledged_at IS NULL AND m.returned_at IS NULL AND "+scope, scope_args).fetchone()['n']
        byloc = conn.execute('SELECT f.current_location AS location,count(*) AS count FROM files f WHERE f.archived=FALSE AND '+scope+' GROUP BY f.current_location ORDER BY count DESC,f.current_location', scope_args).fetchall()
        recent = conn.execute("""SELECT f.id,f.reference_no,f.title,f.state_code,f.current_location,f.current_holder,f.status,f.registered_at,f.due_at,
           CASE WHEN f.status='In Circulation' AND f.due_at < now() THEN 'Overdue'
                WHEN EXISTS (SELECT 1 FROM movements pm WHERE pm.file_id=f.id AND pm.action='DISPATCHED' AND pm.to_location=%s AND pm.acknowledged_at IS NULL AND pm.returned_at IS NULL) THEN 'Awaiting acknowledgement'
                ELSE f.status END AS computed_status
           FROM files f WHERE f.archived=FALSE AND """+scope+' ORDER BY f.registered_at DESC LIMIT 8', ([office] if is_lgi else [''] ) + scope_args).fetchall()
    return jsonify(counts={**counts, 'collected_today': collected, 'unacknowledged': unack}, by_location=byloc, recent=recent, generated_at=datetime.now(timezone.utc).isoformat())


@app.get('/api/audit')
@require_roles(*ADMIN_ROLES,'Read-only Auditor')
def audit_list():
    with db() as conn: rows = conn.execute('SELECT a.*,u.full_name,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 500').fetchall()
    return jsonify(logs=rows)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT','5000')), debug=False)
