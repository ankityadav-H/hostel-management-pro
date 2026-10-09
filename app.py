from __future__ import annotations
import csv, io, os, sqlite3, secrets, shutil
from datetime import date, datetime
from functools import wraps
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, send_file, send_from_directory, abort
BASE = Path(__file__).resolve().parent
INSTANCE = BASE / 'instance'
UPLOADS = BASE / 'uploads' / 'student_photos'
INSTANCE.mkdir(exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)
DB_PATH = INSTANCE / 'hostel.db'
app = Flask(__name__)
app.secret_key = os.environ.get('HOSTEL_SECRET_KEY', 'CHANGE-THIS-SECRET-KEY-BEFORE-DEPLOYMENT-' + secrets.token_hex(8))
app.config.update(MAX_CONTENT_LENGTH=5 * 1024 * 1024, UPLOAD_FOLDER=str(UPLOADS), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','warden','student','maintenance')), full_name TEXT NOT NULL,
 student_id INTEGER, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS students (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, phone TEXT DEFAULT '',
 course TEXT DEFAULT '', branch TEXT DEFAULT '', year TEXT DEFAULT '', batch TEXT DEFAULT '', address TEXT DEFAULT '',
 hostel_name TEXT DEFAULT '', room_number TEXT DEFAULT '', photo TEXT DEFAULT '', joining_date TEXT DEFAULT '',
 leaving_date TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Currently Staying', emergency_contact TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rooms (
 id INTEGER PRIMARY KEY AUTOINCREMENT, room_number TEXT UNIQUE NOT NULL, block_name TEXT DEFAULT '', floor TEXT DEFAULT '',
 capacity INTEGER NOT NULL DEFAULT 2, room_type TEXT DEFAULT 'Standard', notes TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS room_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, room_number TEXT NOT NULL,
 start_date TEXT NOT NULL, end_date TEXT DEFAULT '', notes TEXT DEFAULT '', FOREIGN KEY(student_id) REFERENCES students(id)
);
CREATE TABLE IF NOT EXISTS leave_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, from_date TEXT NOT NULL, to_date TEXT NOT NULL,
 destination TEXT DEFAULT '', reason TEXT NOT NULL, contact_phone TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Pending',
 decision_note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(student_id) REFERENCES students(id)
);
CREATE TABLE IF NOT EXISTS complaints (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER, reporter_name TEXT NOT NULL, room_number TEXT DEFAULT '',
 category TEXT NOT NULL, description TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'Normal', status TEXT NOT NULL DEFAULT 'Pending',
 assigned_to TEXT DEFAULT '', resolution_note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(student_id) REFERENCES students(id)
);
CREATE TABLE IF NOT EXISTS notices (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL, audience TEXT NOT NULL DEFAULT 'All',
 created_by TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS mess_menu (
 id INTEGER PRIMARY KEY AUTOINCREMENT, menu_date TEXT NOT NULL, meal TEXT NOT NULL, items TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(menu_date, meal)
);
CREATE TABLE IF NOT EXISTS fee_records (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, amount REAL NOT NULL, due_date TEXT DEFAULT '',
 period TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Pending', payment_date TEXT DEFAULT '', receipt_ref TEXT DEFAULT '',
 notes TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(student_id) REFERENCES students(id)
);
CREATE TABLE IF NOT EXISTS visitors (
 id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_name TEXT NOT NULL, phone TEXT DEFAULT '', student_id INTEGER,
 purpose TEXT DEFAULT '', entry_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, exit_time TEXT DEFAULT '', approved_by TEXT DEFAULT '',
 FOREIGN KEY(student_id) REFERENCES students(id)
);
CREATE TABLE IF NOT EXISTS lost_found (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, item_type TEXT NOT NULL DEFAULT 'Lost', description TEXT DEFAULT '',
 contact_name TEXT DEFAULT '', contact_phone TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Open', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS activity_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
'''

def db_conn():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop('db', None)
    if db is not None: db.close()

def log_action(action, detail=''):
    if session.get('user_id'):
        db_conn().execute('INSERT INTO activity_log(username, action, detail) VALUES(?,?,?)', (session.get('username',''), action, detail))
        db_conn().commit()

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    if not con.execute('SELECT 1 FROM users WHERE username=?', ('admin',)).fetchone():
        con.execute('INSERT INTO users(username,password_hash,role,full_name) VALUES(?,?,?,?)', ('admin', generate_password_hash(os.environ.get('HOSTEL_ADMIN_PASSWORD','admin123')), 'admin', 'Hostel Administrator'))
    # Seed a few rooms so a fresh demo is immediately usable.
    if con.execute('SELECT COUNT(*) FROM rooms').fetchone()[0] == 0:
        con.executemany('INSERT INTO rooms(room_number,block_name,floor,capacity,room_type) VALUES(?,?,?,?,?)', [
          ('A-101','A','1',2,'Standard'), ('A-102','A','1',3,'Standard'), ('B-201','B','2',2,'Deluxe')])
    con.commit(); con.close()

@app.before_request
def load_user():
    g.user = None
    if session.get('user_id'):
        g.user = db_conn().execute('SELECT * FROM users WHERE id=? AND active=1', (session['user_id'],)).fetchone()
        if g.user is None: session.clear()

@app.context_processor
def inject_globals():
    return {'current_user': g.get('user'), 'today': date.today().isoformat()}

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash('Please log in to continue.', 'warning'); return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user['role'] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

def formval(key, default=''):
    return request.form.get(key, default).strip()

def get_student_for_user():
    if not g.user or not g.user['student_id']: return None
    return db_conn().execute('SELECT * FROM students WHERE id=?', (g.user['student_id'],)).fetchone()

@app.route('/')
def index():
    con = db_conn()
    q = request.args.get('q','').strip()
    status = request.args.get('status','').strip()
    sql = 'SELECT * FROM students WHERE 1=1'; params=[]
    if q:
        sql += ' AND (name LIKE ? OR student_code LIKE ? OR branch LIKE ? OR room_number LIKE ?)'
        params += [f'%{q}%']*4
    if status:
        sql += ' AND status=?'; params.append(status)
    sql += ' ORDER BY name LIMIT 100'
    students = con.execute(sql, params).fetchall()
    stats = {
      'students': con.execute("SELECT COUNT(*) FROM students WHERE status='Currently Staying'").fetchone()[0],
      'rooms': con.execute('SELECT COUNT(*) FROM rooms').fetchone()[0],
      'vacant': con.execute("SELECT COUNT(*) FROM rooms r WHERE (SELECT COUNT(*) FROM students s WHERE s.room_number=r.room_number AND s.status='Currently Staying') < r.capacity").fetchone()[0],
      'pending': con.execute("SELECT COUNT(*) FROM leave_requests WHERE status='Pending'").fetchone()[0],
      'complaints': con.execute("SELECT COUNT(*) FROM complaints WHERE status NOT IN ('Resolved','Closed')").fetchone()[0],
    }
    notices = con.execute('SELECT * FROM notices ORDER BY id DESC LIMIT 5').fetchall()
    return render_template('index.html', students=students, stats=stats, notices=notices, q=q, status=status)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = formval('username'); password = request.form.get('password','')
        user = db_conn().execute('SELECT * FROM users WHERE username=? AND active=1', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear(); session['user_id']=user['id']; session['username']=user['username']
            log_action('Login', 'Signed in'); return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Username or password is incorrect.', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear(); flash('You have been logged out.', 'info'); return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if g.user['role']=='student': return redirect(url_for('student_portal'))
    if g.user['role']=='maintenance': return redirect(url_for('complaints_page'))
    return redirect(url_for('admin_dashboard'))

@app.route('/admin')
@roles_required('admin','warden')
def admin_dashboard():
    con = db_conn()
    stats = {
      'students': con.execute("SELECT COUNT(*) FROM students WHERE status='Currently Staying'").fetchone()[0],
      'rooms': con.execute('SELECT COUNT(*) FROM rooms').fetchone()[0],
      'vacant': con.execute("SELECT COUNT(*) FROM rooms r WHERE (SELECT COUNT(*) FROM students s WHERE s.room_number=r.room_number AND s.status='Currently Staying') < r.capacity").fetchone()[0],
      'leaves': con.execute("SELECT COUNT(*) FROM leave_requests WHERE status='Pending'").fetchone()[0],
      'complaints': con.execute("SELECT COUNT(*) FROM complaints WHERE status NOT IN ('Resolved','Closed')").fetchone()[0],
      'fees': con.execute("SELECT COALESCE(SUM(amount),0) FROM fee_records WHERE status='Pending'").fetchone()[0],
    }
    recent = con.execute('SELECT * FROM activity_log ORDER BY id DESC LIMIT 8').fetchall()
    return render_template('dashboard.html', stats=stats, recent=recent)

@app.route('/students')
def students_list():
    q = request.args.get('q','').strip(); con=db_conn(); sql='SELECT * FROM students WHERE 1=1'; p=[]
    if q:
      sql += ' AND (name LIKE ? OR student_code LIKE ? OR course LIKE ? OR branch LIKE ? OR room_number LIKE ?)'; p += [f'%{q}%']*5
    sql += ' ORDER BY name'
    return render_template('students.html', students=con.execute(sql,p).fetchall(), q=q)

@app.route('/students/<int:sid>')
def student_profile(sid):
    s=db_conn().execute('SELECT * FROM students WHERE id=?',(sid,)).fetchone()
    if not s: abort(404)
    if s['status']!='Currently Staying' and not g.user: pass
    hist=db_conn().execute('SELECT * FROM room_history WHERE student_id=? ORDER BY id DESC',(sid,)).fetchall()
    can_view_private = bool(g.user and (g.user['role'] in ('admin','warden') or (g.user['role']=='student' and g.user['student_id']==sid)))
    return render_template('student_profile.html', student=s, history=hist, can_view_private=can_view_private)

@app.route('/uploads/student_photos/<path:filename>')
def uploaded_student_photo(filename):
    return send_from_directory(
        UPLOADS,
        filename,
        max_age=3600
    )
 
@app.route('/students/add', methods=['GET','POST'])
@roles_required('admin','warden')
def student_add():
    if request.method=='POST':
      code=formval('student_code') or ('STU-'+datetime.now().strftime('%y%m%d%H%M%S'))
      name=formval('name')
      if not name: flash('Student name is required.','danger'); return redirect(url_for('student_add'))
      photo=''
      file=request.files.get('photo')
      if file and file.filename:
        ext=Path(secure_filename(file.filename)).suffix.lower()
        if ext not in {'.png','.jpg','.jpeg','.webp'}: flash('Photo must be PNG, JPG or WEBP.','danger'); return redirect(url_for('student_add'))
        photo=f'{secrets.token_hex(12)}{ext}'; file.save(UPLOADS/photo)
      con=db_conn()
      try:
        cur=con.execute('''INSERT INTO students(student_code,name,phone,course,branch,year,batch,address,hostel_name,room_number,photo,joining_date,status,emergency_contact)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(code,name,formval('phone'),formval('course'),formval('branch'),formval('year'),formval('batch'),formval('address'),formval('hostel_name'),formval('room_number'),photo,formval('joining_date') or date.today().isoformat(),formval('status','Currently Staying'),formval('emergency_contact')))
        sid=cur.lastrowid
        if formval('room_number'):
          con.execute('INSERT INTO room_history(student_id,room_number,start_date,notes) VALUES(?,?,?,?)',(sid,formval('room_number'),formval('joining_date') or date.today().isoformat(),'Initial room allocation'))
        con.commit(); log_action('Added student',f'{code} - {name}'); flash('Student record added.','success'); return redirect(url_for('students_list'))
      except sqlite3.IntegrityError: con.rollback(); flash('Student code already exists. Choose a unique code.','danger')
    rooms=db_conn().execute('SELECT room_number FROM rooms ORDER BY room_number').fetchall()
    return render_template('student_form.html', student=None, rooms=rooms)

@app.route('/students/<int:sid>/edit', methods=['GET','POST'])
@roles_required('admin','warden')
def student_edit(sid):
    con=db_conn(); s=con.execute('SELECT * FROM students WHERE id=?',(sid,)).fetchone()
    if not s: abort(404)
    if request.method=='POST':
      room=formval('room_number'); old=s['room_number']; photo=s['photo']
      file=request.files.get('photo')
      if file and file.filename:
        ext=Path(secure_filename(file.filename)).suffix.lower()
        if ext not in {'.png','.jpg','.jpeg','.webp'}: flash('Photo must be PNG, JPG or WEBP.','danger'); return redirect(url_for('student_edit',sid=sid))
        photo=f'{secrets.token_hex(12)}{ext}'; file.save(UPLOADS/photo)
      try:
        con.execute('''UPDATE students SET student_code=?,name=?,phone=?,course=?,branch=?,year=?,batch=?,address=?,hostel_name=?,room_number=?,photo=?,joining_date=?,leaving_date=?,status=?,emergency_contact=? WHERE id=?''',
          (formval('student_code'),formval('name'),formval('phone'),formval('course'),formval('branch'),formval('year'),formval('batch'),formval('address'),formval('hostel_name'),room,photo,formval('joining_date'),formval('leaving_date'),formval('status'),formval('emergency_contact'),sid))
        if room != old:
          con.execute('UPDATE room_history SET end_date=? WHERE student_id=? AND end_date=\'\'',(date.today().isoformat(),sid))
          if room: con.execute('INSERT INTO room_history(student_id,room_number,start_date,notes) VALUES(?,?,?,?)',(sid,room,date.today().isoformat(),'Room changed'))
        con.commit(); log_action('Edited student',s['student_code']); flash('Student updated.','success'); return redirect(url_for('student_profile',sid=sid))
      except sqlite3.IntegrityError: con.rollback(); flash('Student code already exists.','danger')
    rooms=con.execute('SELECT room_number FROM rooms ORDER BY room_number').fetchall()
    return render_template('student_form.html', student=s, rooms=rooms)

@app.route('/students/<int:sid>/delete', methods=['POST'])
@roles_required('admin')
def student_delete(sid):
    con=db_conn(); s=con.execute('SELECT * FROM students WHERE id=?',(sid,)).fetchone()
    if s:
      con.execute('UPDATE visitors SET student_id=NULL WHERE student_id=?',(sid,))
      con.execute('DELETE FROM users WHERE student_id=?',(sid,))
      con.execute('DELETE FROM fee_records WHERE student_id=?',(sid,))
      con.execute('DELETE FROM leave_requests WHERE student_id=?',(sid,))
      con.execute('DELETE FROM complaints WHERE student_id=?',(sid,))
      con.execute('DELETE FROM room_history WHERE student_id=?',(sid,))
      con.execute('DELETE FROM students WHERE id=?',(sid,)); con.commit(); log_action('Deleted student',s['student_code']); flash('Student record and linked operational records were deleted.','info')
    return redirect(url_for('students_list'))

@app.route('/rooms', methods=['GET','POST'])
def rooms_page():
    con=db_conn()
    if request.method=='POST':
      if not g.user or g.user['role'] not in ('admin','warden'): abort(403)
      try:
        con.execute('INSERT INTO rooms(room_number,block_name,floor,capacity,room_type,notes) VALUES(?,?,?,?,?,?)',(formval('room_number'),formval('block_name'),formval('floor'),max(1,int(formval('capacity','2'))),formval('room_type','Standard'),formval('notes'))); con.commit(); log_action('Added room',formval('room_number')); flash('Room added.','success')
      except (sqlite3.IntegrityError,ValueError): flash('Could not add room. Check that the room number is unique and capacity is a number.','danger')
      return redirect(url_for('rooms_page'))
    rooms=con.execute('''SELECT r.*,(SELECT COUNT(*) FROM students s WHERE s.room_number=r.room_number AND s.status='Currently Staying') AS occupied FROM rooms r ORDER BY block_name,room_number''').fetchall()
    return render_template('rooms.html',rooms=rooms)

@app.route('/leave', methods=['GET','POST'])
@login_required
def leave_page():
    con=db_conn(); linked=get_student_for_user()
    if request.method=='POST':
      sid=int(formval('student_id') or (linked['id'] if linked else 0))
      if g.user['role']=='student' and (not linked or sid!=linked['id']): abort(403)
      if g.user['role'] not in ('student','admin','warden'): abort(403)
      if not formval('from_date') or not formval('to_date') or not formval('reason'): flash('Dates and reason are required.','danger')
      else:
        con.execute('INSERT INTO leave_requests(student_id,from_date,to_date,destination,reason,contact_phone) VALUES(?,?,?,?,?,?)',(sid,formval('from_date'),formval('to_date'),formval('destination'),formval('reason'),formval('contact_phone'))); con.commit(); log_action('Submitted leave request',f'Student {sid}'); flash('Leave request submitted.','success')
      return redirect(url_for('leave_page'))
    if g.user['role']=='student' and linked: rows=con.execute('SELECT l.*,s.name,s.student_code FROM leave_requests l JOIN students s ON s.id=l.student_id WHERE l.student_id=? ORDER BY l.id DESC',(linked['id'],)).fetchall()
    elif g.user['role'] in ('admin','warden'): rows=con.execute('SELECT l.*,s.name,s.student_code FROM leave_requests l JOIN students s ON s.id=l.student_id ORDER BY l.id DESC').fetchall()
    else: rows=[]
    return render_template('leave.html',rows=rows,students=con.execute('SELECT id,name,student_code FROM students ORDER BY name').fetchall(),linked=linked)

@app.route('/leave/<int:rid>/decision', methods=['POST'])
@roles_required('admin','warden')
def leave_decision(rid):
    status=formval('status')
    if status not in ('Approved','Rejected'): abort(400)
    con=db_conn(); con.execute('UPDATE leave_requests SET status=?,decision_note=? WHERE id=?',(status,formval('decision_note'),rid)); con.commit(); log_action('Leave decision',f'Request {rid}: {status}'); flash(f'Leave request {status.lower()}.','success'); return redirect(url_for('leave_page'))

@app.route('/complaints', methods=['GET','POST'])
@login_required
def complaints_page():
    con=db_conn(); linked=get_student_for_user()
    if request.method=='POST':
      reporter=formval('reporter_name') or (linked['name'] if linked else g.user['full_name'])
      student_id=linked['id'] if linked else (int(formval('student_id')) if formval('student_id').isdigit() else None)
      con.execute('INSERT INTO complaints(student_id,reporter_name,room_number,category,description,priority) VALUES(?,?,?,?,?,?)',(student_id,reporter,formval('room_number') or (linked['room_number'] if linked else ''),formval('category','Other'),formval('description'),formval('priority','Normal'))); con.commit(); log_action('Complaint submitted',formval('category')); flash('Complaint submitted.','success'); return redirect(url_for('complaints_page'))
    if g.user['role']=='student' and linked: rows=con.execute('SELECT * FROM complaints WHERE student_id=? ORDER BY id DESC',(linked['id'],)).fetchall()
    else: rows=con.execute('SELECT * FROM complaints ORDER BY id DESC').fetchall()
    return render_template('complaints.html',rows=rows,linked=linked)

@app.route('/complaints/<int:cid>/update',methods=['POST'])
@roles_required('admin','warden','maintenance')
def complaint_update(cid):
    status=formval('status','In Progress')
    if status not in ('Pending','In Progress','Resolved','Closed'): abort(400)
    con=db_conn(); con.execute('UPDATE complaints SET status=?,assigned_to=?,resolution_note=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(status,formval('assigned_to'),formval('resolution_note'),cid)); con.commit(); log_action('Updated complaint',f'{cid}: {status}'); flash('Complaint updated.','success'); return redirect(url_for('complaints_page'))

@app.route('/notices', methods=['GET','POST'])
@login_required
def notices_page():
    con=db_conn()
    if request.method=='POST':
      if g.user['role'] not in ('admin','warden'): abort(403)
      if formval('title') and formval('body'):
        con.execute('INSERT INTO notices(title,body,audience,created_by) VALUES(?,?,?,?)',(formval('title'),formval('body'),formval('audience','All'),g.user['full_name'])); con.commit(); log_action('Published notice',formval('title')); flash('Notice published.','success')
      else: flash('Title and message are required.','danger')
      return redirect(url_for('notices_page'))
    rows=con.execute('SELECT * FROM notices ORDER BY id DESC').fetchall()
    return render_template('notices.html',rows=rows)

@app.route('/mess', methods=['GET','POST'])
@login_required
def mess_page():
    con=db_conn()
    if request.method=='POST':
      if g.user['role'] not in ('admin','warden'): abort(403)
      try:
        con.execute('INSERT INTO mess_menu(menu_date,meal,items) VALUES(?,?,?) ON CONFLICT(menu_date,meal) DO UPDATE SET items=excluded.items',(formval('menu_date'),formval('meal'),formval('items'))); con.commit(); log_action('Updated mess menu',formval('menu_date')); flash('Mess menu saved.','success')
      except sqlite3.Error: flash('Could not save the menu.','danger')
      return redirect(url_for('mess_page'))
    rows=con.execute('SELECT * FROM mess_menu ORDER BY menu_date DESC, meal').fetchall()
    return render_template('mess.html',rows=rows)

@app.route('/fees', methods=['GET','POST'])
@roles_required('admin','warden','student')
def fees_page():
    con=db_conn(); linked=get_student_for_user()
    if request.method=='POST':
      if g.user['role'] not in ('admin','warden'): abort(403)
      try:
        con.execute('INSERT INTO fee_records(student_id,amount,due_date,period,status,payment_date,receipt_ref,notes) VALUES(?,?,?,?,?,?,?,?)',(int(formval('student_id')),float(formval('amount')),formval('due_date'),formval('period'),formval('status','Pending'),formval('payment_date'),formval('receipt_ref'),formval('notes'))); con.commit(); log_action('Added fee record',formval('period')); flash('Fee record added. This module records payments; it does not charge money online.','success')
      except (ValueError,sqlite3.Error): flash('Could not save fee record. Check the values.','danger')
      return redirect(url_for('fees_page'))
    if g.user['role']=='student' and linked: rows=con.execute('SELECT f.*,s.name,s.student_code FROM fee_records f JOIN students s ON s.id=f.student_id WHERE f.student_id=? ORDER BY f.id DESC',(linked['id'],)).fetchall()
    elif g.user['role'] in ('admin','warden'): rows=con.execute('SELECT f.*,s.name,s.student_code FROM fee_records f JOIN students s ON s.id=f.student_id ORDER BY f.id DESC').fetchall()
    else: rows=[]
    return render_template('fees.html',rows=rows,students=con.execute('SELECT id,name,student_code FROM students ORDER BY name').fetchall())

@app.route('/fees/<int:fid>/mark-paid',methods=['POST'])
@roles_required('admin','warden')
def fee_mark_paid(fid):
    con=db_conn(); con.execute("UPDATE fee_records SET status='Paid',payment_date=? WHERE id=?",(formval('payment_date') or date.today().isoformat(),fid)); con.commit(); log_action('Marked fee paid',str(fid)); flash('Fee record marked as paid.','success'); return redirect(url_for('fees_page'))

@app.route('/visitors', methods=['GET','POST'])
@roles_required('admin','warden')
def visitors_page():
    con=db_conn()
    if request.method=='POST':
      con.execute('INSERT INTO visitors(visitor_name,phone,student_id,purpose,approved_by) VALUES(?,?,?,?,?)',(formval('visitor_name'),formval('phone'),int(formval('student_id')) if formval('student_id').isdigit() else None,formval('purpose'),g.user['full_name'])); con.commit(); log_action('Visitor entry',formval('visitor_name')); flash('Visitor entry recorded.','success'); return redirect(url_for('visitors_page'))
    rows=con.execute('SELECT v.*,s.name AS student_name FROM visitors v LEFT JOIN students s ON s.id=v.student_id ORDER BY v.id DESC').fetchall()
    return render_template('visitors.html',rows=rows,students=con.execute('SELECT id,name,student_code FROM students ORDER BY name').fetchall())

@app.route('/visitors/<int:vid>/checkout',methods=['POST'])
@roles_required('admin','warden')
def visitor_checkout(vid):
    con=db_conn(); con.execute("UPDATE visitors SET exit_time=CURRENT_TIMESTAMP WHERE id=? AND exit_time=''",(vid,)); con.commit(); log_action('Visitor checkout',str(vid)); return redirect(url_for('visitors_page'))

@app.route('/lost-found',methods=['GET','POST'])
@login_required
def lost_found_page():
    con=db_conn()
    if request.method=='POST':
      con.execute('INSERT INTO lost_found(title,item_type,description,contact_name,contact_phone) VALUES(?,?,?,?,?)',(formval('title'),formval('item_type','Lost'),formval('description'),formval('contact_name') or g.user['full_name'],formval('contact_phone'))); con.commit(); log_action('Lost and found post',formval('title')); flash('Item posted.','success'); return redirect(url_for('lost_found_page'))
    rows=con.execute('SELECT * FROM lost_found ORDER BY id DESC').fetchall()
    return render_template('lost_found.html',rows=rows)

@app.route('/lost-found/<int:iid>/close',methods=['POST'])
@roles_required('admin','warden')
def lost_found_close(iid):
    db_conn().execute("UPDATE lost_found SET status='Closed' WHERE id=?",(iid,)); db_conn().commit(); log_action('Closed lost/found item',str(iid)); return redirect(url_for('lost_found_page'))

@app.route('/accounts',methods=['GET','POST'])
@roles_required('admin')
def accounts_page():
    con=db_conn()
    if request.method=='POST':
      username=formval('username'); password=request.form.get('password',''); role=formval('role'); full_name=formval('full_name'); sid=int(formval('student_id')) if formval('student_id').isdigit() else None
      if not username or len(password)<8 or not full_name or role not in ('admin','warden','student','maintenance'):
        flash('Username, full name, valid role and password of at least 8 characters are required.','danger')
      else:
        try:
          con.execute('INSERT INTO users(username,password_hash,role,full_name,student_id) VALUES(?,?,?,?,?)',(username,generate_password_hash(password),role,full_name,sid)); con.commit(); log_action('Created account',f'{username} ({role})'); flash('Account created.','success')
        except sqlite3.IntegrityError: flash('Username already exists.','danger')
      return redirect(url_for('accounts_page'))
    users=con.execute('SELECT u.*,s.name AS student_name FROM users u LEFT JOIN students s ON s.id=u.student_id ORDER BY u.id').fetchall()
    students=con.execute('SELECT id,name,student_code FROM students ORDER BY name').fetchall()
    return render_template('accounts.html',users=users,students=students)

@app.route('/accounts/<int:uid>/toggle',methods=['POST'])
@roles_required('admin')
def account_toggle(uid):
    if uid==g.user['id']: flash('You cannot disable your own active account.','warning')
    else:
      con=db_conn(); con.execute('UPDATE users SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(uid,)); con.commit(); log_action('Toggled account',str(uid)); flash('Account status updated.','success')
    return redirect(url_for('accounts_page'))

@app.route('/reports')
@roles_required('admin','warden')
def reports_page():
    con=db_conn()
    data={
      'students_by_status':con.execute('SELECT status,COUNT(*) n FROM students GROUP BY status').fetchall(),
      'rooms':con.execute("SELECT r.*, (SELECT COUNT(*) FROM students s WHERE s.room_number=r.room_number AND s.status='Currently Staying') occupied FROM rooms r ORDER BY room_number").fetchall(),
      'complaints':con.execute('SELECT status,COUNT(*) n FROM complaints GROUP BY status').fetchall(),
      'fees':con.execute('SELECT status,COALESCE(SUM(amount),0) total FROM fee_records GROUP BY status').fetchall(),
    }
    return render_template('reports.html',data=data)

@app.route('/export/students.csv')
@roles_required('admin','warden')
def export_students():
    rows=db_conn().execute('SELECT student_code,name,phone,course,branch,year,batch,hostel_name,room_number,joining_date,leaving_date,status FROM students ORDER BY name').fetchall()
    out=io.StringIO(); writer=csv.writer(out); writer.writerow(rows[0].keys() if rows else ['student_code','name','phone','course','branch','year','batch','hostel_name','room_number','joining_date','leaving_date','status']); writer.writerows([tuple(r) for r in rows])
    return send_file(io.BytesIO(out.getvalue().encode('utf-8-sig')), mimetype='text/csv', as_attachment=True, download_name='hostel_students.csv')

@app.route('/backup')
@roles_required('admin')
def backup_db():
    stamp=datetime.now().strftime('%Y%m%d-%H%M%S'); target=INSTANCE/f'hostel-backup-{stamp}.db'
    src=sqlite3.connect(DB_PATH); dest=sqlite3.connect(target)
    src.backup(dest); dest.close(); src.close()
    return send_file(target,as_attachment=True,download_name=target.name)

@app.route('/student-portal')
@roles_required('student')
def student_portal():
    s=get_student_for_user()
    if not s: flash('Your account is not linked to a student record. Contact the administrator.','warning'); return redirect(url_for('index'))
    con=db_conn()
    leaves=con.execute('SELECT * FROM leave_requests WHERE student_id=? ORDER BY id DESC',(s['id'],)).fetchall()
    fees=con.execute('SELECT * FROM fee_records WHERE student_id=? ORDER BY id DESC',(s['id'],)).fetchall()
    complaints=con.execute('SELECT * FROM complaints WHERE student_id=? ORDER BY id DESC',(s['id'],)).fetchall()
    return render_template('student_portal.html',student=s,leaves=leaves,fees=fees,complaints=complaints)

@app.route('/change-password',methods=['GET','POST'])
@login_required
def change_password():
    if request.method=='POST':
      old=request.form.get('old_password',''); new=request.form.get('new_password','')
      row=db_conn().execute('SELECT password_hash FROM users WHERE id=?',(g.user['id'],)).fetchone()
      if not check_password_hash(row['password_hash'],old): flash('Current password is incorrect.','danger')
      elif len(new)<8: flash('New password must be at least 8 characters.','danger')
      else:
        db_conn().execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),g.user['id'])); db_conn().commit(); log_action('Changed password'); flash('Password changed.','success'); return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/qr/<int:sid>')
@roles_required('admin','warden')
def student_qr(sid):
    s=db_conn().execute('SELECT * FROM students WHERE id=?',(sid,)).fetchone()
    if not s: abort(404)
    try:
      import qrcode
      from flask import Response
      img=qrcode.make(url_for('student_profile',sid=sid,_external=True))
      buf=io.BytesIO(); img.save(buf,format='PNG'); return send_file(io.BytesIO(buf.getvalue()),mimetype='image/png',download_name=f'{s["student_code"]}-qr.png')
    except ImportError:
      flash('QR library missing. Install dependencies using requirements.txt.','warning'); return redirect(url_for('student_profile',sid=sid))

@app.errorhandler(403)
def forbidden(_): return render_template('error.html',code=403,message='You do not have permission to open this page.'),403
@app.errorhandler(404)
def not_found(_): return render_template('error.html',code=404,message='The page or record could not be found.'),404

with app.app_context():
    init_db()

if __name__ == '__main__':
    print('Hostel Management Pro is starting at http://127.0.0.1:5000')
    print('Default admin login: admin / admin123 (change this after first login).')
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
