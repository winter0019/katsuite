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
        # Default branches are inserted only when absent.
        for name, kind, loc in [
            ('State Coordinator Office','State Office','Katsina State Secretariat'),
            ('Central Registry','Registry','Katsina State Secretariat'),
            ('CIM','Secretariat Branch','Katsina State Secretariat'),
            ('CW&HS','Secretariat Branch','Katsina State Secretariat'),
            ('CDS','Secretariat Branch','Katsina State Secretariat'),
            ('Other Secretariat Branch/Unit','Secretariat Branch','Katsina State Secretariat')]:
            conn.execute('INSERT INTO branches(name, branch_type, location) VALUES (%s,%s,%s) ON CONFLICT(name) DO NOTHING', (name,kind,loc))
        # Seed the approved zonal destinations. Existing branch records are preserved.
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
    # Compact signed bearer token with expiry; no external JWT dependency.
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
    """Return a parameterized visibility predicate for the logged-in office."""
    role = user['role']
    office = (user.get('branch_name') or '').strip()
    if role in ('State Coordinator Admin', 'Central Registry'):
        return 'TRUE', []
    if role in ('Branch Head', 'Registry Officer'):
        if not office:
            return 'FALSE', []
        return (f"({alias}.current_location=%s OR {alias}.originating_office=%s OR EXISTS (SELECT 1 FROM movements sm WHERE sm.file_id={alias}.id AND sm.to_location=%s))", [office, office, office])
    if role == 'Local Government Inspector':
        if not office:
            return 'FALSE', []
        return (f"({alias}.originating_office=%s OR {alias}.current_location=%s OR EXISTS (SELECT 1 FROM movements sm WHERE sm.file_id={alias}.id AND sm.to_location=%s))", [office, office, office])
    if role == 'Zonal Inspector':
        if not office:
            return 'FALSE', []
        # Zone officers can view files originating from, currently held by, or routed to their zone/LGAs.
        return (f"({alias}.current_location=%s OR {alias}.originating_office IN (SELECT name FROM branches WHERE branch_type='LGA Office' AND location=%s) OR EXISTS (SELECT 1 FROM movements sm WHERE sm.file_id={alias}.id AND (sm.to_location=%s OR sm.to_location IN (SELECT name FROM branches WHERE branch_type='LGA Office' AND location=%s))))", [office, office, office, office])
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

@app.post('/api/setup/admin')
def setup_admin():
    data = get_json()
    setup_key = os.environ.get('SETUP_KEY','')
    if not setup_key or not hmac.compare_digest(str(data.get('setup_key','')), setup_key): return bad('Invalid setup key.', 403)
    if not all(data.get(k) for k in ('full_name','username','password')): return bad('full_name, username and password are required.')
    if len(str(data['password'])) < 12: return bad('Use a password of at least 12 characters.')
    try:
        init_db()
        with db() as conn:
            if conn.execute('SELECT count(*) AS n FROM users').fetchone()['n']:
                return bad('Initial setup is locked because an account already exists.', 409)
            branch = conn.execute("SELECT id FROM branches WHERE name='State Coordinator Office'").fetchone()
            conn.execute('INSERT INTO users(full_name,username,password_hash,role,branch_id) VALUES(%s,%s,%s,%s,%s)',
                         (data['full_name'].strip(), data['username'].strip().lower(), pw_hash(str(data['password'])), 'State Coordinator Admin', branch['id']))
        return jsonify(message='Initial State Coordinator administrator created. Remove/rotate SETUP_KEY in Render now.'), 201
    except psycopg.errors.UniqueViolation: return bad('That username already exists.', 409)
    except Exception as exc:
        app.logger.exception('Admin setup failed')
        return bad('Setup failed. Check backend configuration and logs.', 500)

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

@app.post('/api/branches')
@require_roles(*ADMIN_ROLES)
def branch_create():
    d=get_json()
    if not d.get('name'): return bad('Branch name is required.')
    try:
        with db() as conn:
            row=conn.execute('INSERT INTO branches(name,branch_type,location) VALUES(%s,%s,%s) RETURNING id,name,branch_type,location,active', (d['name'].strip(),d.get('branch_type','Secretariat Branch'),d.get('location','Katsina State Secretariat'))).fetchone()
        audit('create','branch',row['id'],row['name']); return jsonify(branch=row),201
    except psycopg.errors.UniqueViolation: return bad('A branch with that name already exists.',409)

@app.post('/api/users')
@require_roles(*ADMIN_ROLES)
def user_create():
    d=get_json()
    if not all(d.get(k) for k in ('full_name','username','password','role')): return bad('Full name, username, password and role are required.')
    if d['role'] not in ROLES: return bad('Invalid role.')
    if len(str(d['password'])) < 12: return bad('Use a password of at least 12 characters.')
    branch_id=d.get('branch_id') or None
    try:
        with db() as conn:
            row=conn.execute('INSERT INTO users(full_name,username,password_hash,role,branch_id) VALUES(%s,%s,%s,%s,%s) RETURNING id,full_name,username,role,branch_id,active,created_at', (d['full_name'].strip(),d['username'].strip().lower(),pw_hash(str(d['password'])),d['role'],branch_id)).fetchone()
        audit('create','user',row['id'],f"{row['username']} / {row['role']}"); return jsonify(user=row),201
    except psycopg.errors.UniqueViolation: return bad('Username already exists.',409)

@app.get('/api/users')
@require_roles(*ADMIN_ROLES)
def users_list():
    with db() as conn: rows=conn.execute('SELECT u.id,u.full_name,u.username,u.role,u.branch_id,u.active,u.created_at,b.name AS branch_name FROM users u LEFT JOIN branches b ON b.id=u.branch_id ORDER BY u.full_name').fetchall()
    return jsonify(users=rows)

@app.patch('/api/users/<int:user_id>')
@require_roles(*ADMIN_ROLES)
def user_update(user_id):
    d=get_json()
    with db() as conn:
        target=conn.execute('SELECT id,active FROM users WHERE id=%s',(user_id,)).fetchone()
        if not target: return bad('User not found.',404)
        active=bool(d.get('active',target['active']))
        if user_id==g.user['id'] and not active: return bad('You cannot deactivate your own account.',400)
        conn.execute('UPDATE users SET active=%s WHERE id=%s',(active,user_id))
    audit('update','user',user_id,f'active={active}'); return jsonify(message='Account updated.')

@app.post('/api/files')
@require_roles('Central Registry', 'Registry Officer')
def file_create():
    if not is_central_registry(g.user): return bad('Only Central Registry staff may register a new file.', 403)
    d=get_json()
    if not d.get('title'): return bad('Please select a purpose for collecting the file.')
    with db() as conn:
        seq=conn.execute("SELECT nextval(pg_get_serial_sequence('files','id')) AS n").fetchone()['n']
        ref=f"KNS-FM-{datetime.now().year}-{seq:06d}"
        try:
            row=conn.execute('''INSERT INTO files(id,reference_no,title,subject,state_code,originating_office,current_location,current_holder,registered_by,due_at,notes)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''', (seq,ref,d['title'].strip(),d.get('subject','').strip(),d.get('state_code','').strip().upper(),'Central Registry','Central Registry',g.user['full_name'],g.user['id'],d.get('due_at') or None,d.get('notes','').strip())).fetchone()
            conn.execute("INSERT INTO movements(file_id,action,from_location,to_location,sender,recipient,acknowledged_at,created_by,remarks) VALUES(%s,'REGISTERED','',%s,%s,%s,now(),%s,'Initial file registration')", (seq,'Central Registry','Central Registry',g.user['full_name'],g.user['id']))
            # If a destination is selected during registration, create a tracked dispatch from Central Registry.
            destination=(d.get('destination_office') or '').strip()
            if destination:
                recipient=(d.get('recipient') or '').strip() or 'Receiving officer to be confirmed'
                due=d.get('due_at') or None
                conn.execute("INSERT INTO movements(file_id,action,from_location,to_location,sender,recipient,due_at,remarks,created_by) VALUES(%s,'DISPATCHED',%s,%s,%s,%s,%s,%s,%s)", (seq,row['current_location'],destination,g.user['full_name'],recipient,due,'Dispatched from Central Registry; awaiting acknowledgement',g.user['id']))
                conn.execute("UPDATE files SET current_location=%s,current_holder=%s,status='In Transit',due_at=%s WHERE id=%s", (destination,recipient,due,seq))
                row['current_location']=destination; row['current_holder']=recipient; row['status']='In Transit'; row['due_at']=due
        except Exception: raise
    audit('register','file',row['id'],ref); return jsonify(file=row),201

@app.get('/api/files')
@require_roles(*ALL_READ_ROLES)
def files_list():
    q=(request.args.get('q') or '').strip(); loc=(request.args.get('location') or '').strip(); status=(request.args.get('status') or '').strip()
    start=(request.args.get('start') or '').strip(); end=(request.args.get('end') or '').strip()
    scope, scope_args = office_scope_sql(g.user, 'f')
    sql='''SELECT f.*, CASE WHEN f.status='In Circulation' AND f.due_at IS NOT NULL AND f.due_at < now() THEN 'Overdue' ELSE f.status END AS computed_status FROM files f WHERE f.archived=FALSE AND ''' + scope
    args=list(scope_args)
    if q:
        sql += " AND (f.reference_no ILIKE %s OR f.title ILIKE %s OR f.subject ILIKE %s OR f.state_code ILIKE %s OR f.current_holder ILIKE %s)"
        args += [f'%{q}%']*5
    if loc and loc!='All locations': sql += ' AND f.current_location=%s'; args.append(loc)
    if start: sql += ' AND f.registered_at >= %s::date'; args.append(start)
    if end: sql += " AND f.registered_at < (%s::date + interval '1 day')"; args.append(end)
    if status: sql += " AND (CASE WHEN f.status='In Circulation' AND f.due_at IS NOT NULL AND f.due_at < now() THEN 'Overdue' ELSE f.status END)=%s"; args.append(status)
    sql += ' ORDER BY f.registered_at DESC LIMIT 500'
    with db() as conn: rows=conn.execute(sql,args).fetchall()
    return jsonify(files=rows)

@app.get('/api/files/<int:file_id>')
@require_roles(*ALL_READ_ROLES)
def file_detail(file_id):
    with db() as conn:
        f=conn.execute("SELECT f.*, CASE WHEN f.status='In Circulation' AND f.due_at IS NOT NULL AND f.due_at < now() THEN 'Overdue' ELSE f.status END AS computed_status FROM files f WHERE f.id=%s",(file_id,)).fetchone()
        if not f or not user_can_access_file(conn, g.user, file_id): return bad('File not found or you do not have access to this file.',404)
        moves=conn.execute('SELECT * FROM movements WHERE file_id=%s ORDER BY dispatched_at DESC,id DESC',(file_id,)).fetchall()
    return jsonify(file=f,movements=moves)

def next_file_destinations(conn, user):
    role = user['role']
    office = (user.get('branch_name') or '').strip()
    if role in ('Central Registry', 'Registry Officer'):
        if not is_central_registry(user):
            return []
        # Direct collection is allowed for LGIs, ZIs, branches/units and State Coordinator.
        return [r['name'] for r in conn.execute(
            "SELECT name FROM branches WHERE active=TRUE AND name <> 'Central Registry' ORDER BY name"
        ).fetchall()]
    if role == 'Local Government Inspector':
        zone = conn.execute("SELECT location FROM branches WHERE name=%s AND branch_type='LGA Office'", (office,)).fetchone()
        if not zone:
            return []
        return [r['name'] for r in conn.execute(
            "SELECT name FROM branches WHERE branch_type='Zonal Office' AND name=%s", (zone['location'],)
        ).fetchall()]
    if role == 'Zonal Inspector':
        return [r['name'] for r in conn.execute(
            "SELECT name FROM branches WHERE branch_type='Secretariat Branch' AND active=TRUE ORDER BY name"
        ).fetchall()]
    if role == 'Branch Head':
        return ['State Coordinator Office']
    return []


@app.post('/api/files/<int:file_id>/dispatch')
@require_roles('Central Registry', 'Registry Officer', 'Local Government Inspector', 'Zonal Inspector', 'Branch Head')
def dispatch_file(file_id):
    d = get_json()
    destination = (d.get('to_location') or '').strip()
    recipient = (d.get('recipient') or '').strip()
    if not destination or not recipient:
        return bad('Destination and receiving officer are required.')
    with db() as conn:
        f = conn.execute('SELECT * FROM files WHERE id=%s AND archived=FALSE FOR UPDATE', (file_id,)).fetchone()
        if not f:
            return bad('File not found.', 404)
        role = g.user['role']
        current_location = (f['current_location'] or '').strip()
        if role in ('Central Registry', 'Registry Officer') and not is_central_registry(g.user):
            return bad('Only Central Registry staff may dispatch files from Central Registry.', 403)
        if current_location.casefold() != (g.user.get('branch_name') or '').strip().casefold():
            return bad('Your office does not currently hold this file.', 403)
        if f['status'] == 'In Transit' or f['status'] == 'Archived':
            return bad('This file is in transit or archived and cannot be forwarded.', 409)
        allowed = next_file_destinations(conn, g.user)
        if destination.casefold() not in {x.casefold() for x in allowed}:
            return bad('This destination is not permitted in the file movement workflow.', 403)
        due = d.get('due_at') or None
        m = conn.execute('''INSERT INTO movements(file_id,action,from_location,to_location,sender,recipient,due_at,remarks,created_by)
          VALUES(%s,'DISPATCHED',%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
          (file_id, current_location, destination, g.user['full_name'], recipient, due, d.get('remarks',''), g.user['id'])).fetchone()
        conn.execute("UPDATE files SET current_location=%s,current_holder=%s,status='In Transit',due_at=%s WHERE id=%s",
                     (destination, recipient, due, file_id))
    audit('dispatch','file',file_id,f"from={current_location}; to={destination}; recipient={recipient}")
    return jsonify(message='File dispatch recorded. Awaiting physical receipt acknowledgement.', movement_id=m['id']), 201

@app.post('/api/movements/<int:movement_id>/acknowledge')
@require_roles('Central Registry', 'Registry Officer', 'Branch Head', 'Zonal Inspector', 'Local Government Inspector', 'State Coordinator Admin')
def acknowledge_movement(movement_id):
    d=get_json()
    with db() as conn:
        m=conn.execute('SELECT * FROM movements WHERE id=%s',(movement_id,)).fetchone()
        if not m: return bad('Movement not found.',404)
        role = g.user['role']
        assigned_office = (g.user.get('branch_name') or '').strip()
        destination = (m['to_location'] or '').strip()
        if role in ('Central Registry', 'Registry Officer'):
            if not is_central_registry(g.user) or destination.casefold() != 'central registry':
                return bad('Only Central Registry staff may acknowledge deliveries addressed to Central Registry.', 403)
        elif role == 'State Coordinator Admin':
            if destination.casefold() != 'state coordinator office':
                return bad('The delivery is not addressed to the State Coordinator Office.', 403)
        elif not assigned_office or destination.casefold() != assigned_office.casefold():
            return bad('You may acknowledge only deliveries addressed to your assigned office.', 403)
        if m['acknowledged_at']: return bad('This delivery has already been acknowledged.',409)
        conn.execute('UPDATE movements SET acknowledged_at=now(),remarks=CASE WHEN %s<>\'\' THEN remarks || E\'\\n\' || %s ELSE remarks END WHERE id=%s',(d.get('remarks',''),d.get('remarks',''),movement_id))
        conn.execute("UPDATE files SET status='In Circulation',current_location=%s,current_holder=%s WHERE id=%s",(m['to_location'],m['recipient'],m['file_id']))
    audit('acknowledge','movement',movement_id,'Receipt acknowledged'); return jsonify(message='Receipt acknowledged.')

@app.post('/api/files/<int:file_id>/return')
@require_roles('Central Registry', 'Registry Officer', 'Branch Head')
def return_file(file_id):
    d=get_json()
    with db() as conn:
        f=conn.execute('SELECT * FROM files WHERE id=%s AND archived=FALSE FOR UPDATE',(file_id,)).fetchone()
        if not f: return bad('File not found.',404)
        if g.user['role'] in ('Registry Officer', 'Branch Head') and f['current_location'] != g.user.get('branch_name'):
            return bad('You may act only on files currently held by your assigned office.',403)
        if g.user['role'] == 'Central Registry' and f['current_location'] != 'Central Registry':
            return bad('Central Registry may record a return only when the file is physically at Central Registry.',403)
        m=conn.execute("SELECT * FROM movements WHERE file_id=%s AND action='DISPATCHED' AND returned_at IS NULL ORDER BY id DESC LIMIT 1",(file_id,)).fetchone()
        if not m: return bad('No outstanding dispatch was found for this file.',409)
        location=(d.get('return_location') or 'Central Registry').strip()
        conn.execute('UPDATE movements SET returned_at=now() WHERE id=%s',(m['id'],))
        conn.execute("INSERT INTO movements(file_id,action,from_location,to_location,sender,recipient,acknowledged_at,returned_at,remarks,created_by) VALUES(%s,'RETURNED',%s,%s,%s,%s,now(),now(),%s,%s)",(file_id,f['current_location'],location,g.user['full_name'],d.get('received_by','Central Registry'),d.get('remarks',''),g.user['id']))
        conn.execute("UPDATE files SET current_location=%s,current_holder=%s,status='Returned',due_at=NULL WHERE id=%s",(location,d.get('received_by','Central Registry'),file_id))
    audit('return','file',file_id,f'returned to {location}'); return jsonify(message='File return recorded.')

@app.get('/api/dashboard')
@require_roles(*ALL_READ_ROLES)
def dashboard():
    scope, scope_args = office_scope_sql(g.user, 'f')
    with db() as conn:
        counts=conn.execute("""SELECT
          count(*) AS total_files,
          count(*) FILTER (WHERE f.registered_at::date=current_date) AS registered_today,
          count(*) FILTER (WHERE f.status='Returned' AND f.id IN (SELECT file_id FROM movements WHERE action='RETURNED' AND returned_at::date=current_date)) AS returned_today,
          count(*) FILTER (WHERE f.status='In Circulation') AS circulating,
          count(*) FILTER (WHERE f.status='In Transit') AS in_transit,
          count(*) FILTER (WHERE f.status='In Circulation' AND f.due_at < now()) AS overdue
          FROM files f WHERE f.archived=FALSE AND """+scope, scope_args).fetchone()
        unack=conn.execute("SELECT count(*) AS n FROM movements m JOIN files f ON f.id=m.file_id WHERE m.action='DISPATCHED' AND m.acknowledged_at IS NULL AND m.returned_at IS NULL AND "+scope,scope_args).fetchone()['n']
        byloc=conn.execute('SELECT f.current_location AS location,count(*) AS count FROM files f WHERE f.archived=FALSE AND '+scope+' GROUP BY f.current_location ORDER BY count DESC,f.current_location',scope_args).fetchall()
        daily=conn.execute('SELECT f.registered_at::date AS day,count(*) AS count FROM files f WHERE f.archived=FALSE AND f.registered_at >= current_date-6 AND '+scope+' GROUP BY f.registered_at::date ORDER BY f.registered_at::date',scope_args).fetchall()
        recent=conn.execute("""SELECT f.id,f.reference_no,f.title,f.state_code,f.current_location,f.current_holder,f.status,f.registered_at,f.due_at,
           CASE WHEN f.status='In Circulation' AND f.due_at < now() THEN 'Overdue' ELSE f.status END AS computed_status
           FROM files f WHERE f.archived=FALSE AND """+scope+' ORDER BY f.registered_at DESC LIMIT 8',scope_args).fetchall()
    return jsonify(counts={**counts,'unacknowledged':unack},by_location=byloc,daily=daily,recent=recent,generated_at=datetime.now(timezone.utc).isoformat())

@app.get('/api/reports/movements')
@require_roles(*ALL_READ_ROLES)
def report_movements():
    start=request.args.get('start'); end=request.args.get('end')
    scope, scope_args = office_scope_sql(g.user, 'f')
    sql='''SELECT m.id,m.action,m.from_location,m.to_location,m.sender,m.recipient,m.dispatched_at,m.acknowledged_at,m.due_at,m.returned_at,m.remarks,f.reference_no,f.title,f.state_code FROM movements m JOIN files f ON f.id=m.file_id WHERE '''+scope; args=list(scope_args)
    if start: sql+=' AND m.dispatched_at >= %s::date'; args.append(start)
    if end: sql+=" AND m.dispatched_at < (%s::date + interval '1 day')"; args.append(end)
    sql+=' ORDER BY m.dispatched_at DESC LIMIT 2000'
    with db() as conn: rows=conn.execute(sql,args).fetchall()
    return jsonify(movements=rows)

@app.get('/api/audit')
@require_roles(*ADMIN_ROLES,'Read-only Auditor')
def audit_list():
    with db() as conn: rows=conn.execute('SELECT a.*,u.full_name,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 500').fetchall()
    return jsonify(logs=rows)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT','5000')), debug=False)