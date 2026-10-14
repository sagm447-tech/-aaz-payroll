import os,sqlite3,json,secrets,hashlib,hmac,base64,datetime,io,csv
from functools import wraps
from flask import Flask,request,session,redirect,url_for,render_template_string,abort,Response,flash
from werkzeug.security import generate_password_hash,check_password_hash
app=Flask(__name__)
app.secret_key=os.environ.get('SECRET_KEY',secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('HTTPS_ONLY')=='1',MAX_CONTENT_LENGTH=3*1024*1024)
DB=os.environ.get('DATABASE_PATH','aaz.db')
def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c
def init():
 with db() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','supervisor','courier')),active INTEGER DEFAULT 1);
 CREATE TABLE IF NOT EXISTS workers(id INTEGER PRIMARY KEY,name TEXT NOT NULL,iqama TEXT UNIQUE NOT NULL,store TEXT NOT NULL,position TEXT,salary REAL DEFAULT 0,supervisor_id INTEGER REFERENCES users(id),active INTEGER DEFAULT 1);
 CREATE TABLE IF NOT EXISTS assignments(user_id INTEGER,store TEXT,PRIMARY KEY(user_id,store));
 CREATE TABLE IF NOT EXISTS receipts(id INTEGER PRIMARY KEY,worker_id INTEGER NOT NULL REFERENCES workers(id),month TEXT NOT NULL,amount REAL NOT NULL,method TEXT NOT NULL,signature TEXT,notes TEXT,operator_id INTEGER NOT NULL REFERENCES users(id),created TEXT NOT NULL,UNIQUE(worker_id,month));
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor INTEGER,action TEXT,details TEXT,created TEXT);''')
  if not c.execute('SELECT 1 FROM users').fetchone():
   password=os.environ.get('ADMIN_PASSWORD')
   if not password or len(password)<12: raise RuntimeError('Set ADMIN_PASSWORD to a strong password of at least 12 characters before first run')
   c.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(os.environ.get('ADMIN_USERNAME','admin'),generate_password_hash(password),'admin'))
  if not c.execute('SELECT 1 FROM workers').fetchone() and os.environ.get('IMPORT_SAMPLE')=='1':
   path=os.path.join(os.path.dirname(__file__),'import_workers.json')
   for x in json.load(open(path,encoding='utf8')):
    if not x.get('iqama'):continue
    c.execute('INSERT OR IGNORE INTO workers(name,iqama,store,position,salary) VALUES(?,?,?,?,?)',(x['name'],str(x['iqama']),str(x['store']),x.get('position',''),float(x.get('payable') or 0)))
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def log(c,action,details):c.execute('INSERT INTO audit(actor,action,details,created) VALUES(?,?,?,?)',(session.get('uid'),action,details,now()))
def logged(fn):
 @wraps(fn)
 def inner(*a,**kw):
  if not session.get('uid'):return redirect('/login')
  with db() as c:u=c.execute('SELECT * FROM users WHERE id=? AND active=1',(session['uid'],)).fetchone()
  if not u:session.clear();return redirect('/login')
  return fn(*a,**kw)
 return inner
def admin(fn):
 @logged
 @wraps(fn)
 def inner(*a,**kw):
  if session.get('role')!='admin':abort(403)
  return fn(*a,**kw)
 return inner
def csrf():
 if not hmac.compare_digest(request.form.get('csrf',''),session.get('csrf','')):abort(400,'Invalid CSRF token')
def formtoken():return '<input type="hidden" name="csrf" value="'+session['csrf']+'">'
def allowed(c,w):
 if session['role']=='admin':return True
 if w['supervisor_id']==session['uid']:return True
 return bool(c.execute('SELECT 1 FROM assignments WHERE user_id=? AND store=?',(session['uid'],w['store'])).fetchone())
BASE='''<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AAZ | الرواتب</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f6fb;font-family:Tahoma,Arial;color:#132742}header{background:#142c4d;color:white;padding:18px 5%;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}a{color:#1763b0;text-decoration:none}header a{color:white;margin:0 7px}main{max-width:1280px;margin:22px auto;padding:0 15px}.card{background:white;border:1px solid #e0e6ef;border-radius:13px;padding:18px;margin:12px 0;box-shadow:0 3px 12px #102a4210}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.metric{font-size:27px;font-weight:bold;color:#15549a}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:11px 8px;border-bottom:1px solid #e6eaf0;text-align:right}th{background:#eef4fb}.scroll{overflow-x:auto}input,select,textarea{padding:10px;border:1px solid #cbd5e1;border-radius:7px;max-width:100%;font:inherit}button,.btn{display:inline-block;background:#185ca6;color:white;padding:10px 15px;border:0;border-radius:7px;cursor:pointer;font:inherit}button:disabled{opacity:.5}label{display:inline-block;margin:6px}small,.muted{color:#66758a}.error{color:#b42318}.notice{background:#fff3d4;padding:12px;border-radius:8px}canvas{border:1px dashed #9ba9bd;touch-action:none;width:100%;height:180px;background:white}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}</style></head><body><header><b>AAZ | إدارة وتسليم رواتب العمال</b>{% if session.get('uid') %}<nav><a href="/">العمال والتسليم</a>{% if session.get('role')=='admin' %}<a href="/users">المشرفون</a><a href="/assign">توزيع الفروع</a><a href="/workers/new">إضافة عامل</a><a href="/audit">سجل التدقيق</a>{% endif %}<a href="/reports">التقارير</a><a href="/rentals">إيجارات سكن العمال</a><a href="/alerts">التنبيهات</a><a href="/logout">خروج</a></nav>{% endif %}</header><main>{% for msg in get_flashed_messages() %}<div class="notice">{{msg}}</div>{% endfor %}{{body|safe}}</main></body></html>'''
def page(body,**ctx):return render_template_string(BASE,body=render_template_string(body,csrf=formtoken(),**ctx))
@app.before_request
def setup():
 if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(24)
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  csrf();u=request.form.get('username','');p=request.form.get('password','')
  with db() as c:user=c.execute('SELECT * FROM users WHERE username=? AND active=1',(u,)).fetchone()
  if user and check_password_hash(user['password'],p):
   session.clear();session.update(uid=user['id'],role=user['role'],csrf=secrets.token_urlsafe(24));return redirect('/')
  flash('اسم المستخدم أو كلمة المرور غير صحيحة')
 return page('<div class="card" style="max-width:430px;margin:50px auto"><h2>دخول النظام</h2><form method="post">{{csrf|safe}}<p><input required name="username" placeholder="اسم المستخدم"></p><p><input required name="password" type="password" placeholder="كلمة المرور"></p><button>دخول</button></form></div>')
@app.route('/logout')
def logout():session.clear();return redirect('/login')
@app.route('/')
@logged
def index():
 with db() as c:
  rows=c.execute('SELECT w.*,u.username supervisor FROM workers w LEFT JOIN users u ON u.id=w.supervisor_id WHERE w.active=1 ORDER BY w.store,w.name').fetchall()
  rows=[dict(x) for x in rows if allowed(c,x)]
  counts=c.execute('SELECT COUNT(*) total,COALESCE(SUM(amount),0) paid FROM receipts').fetchone() if session['role']=='admin' else None
  done={x['worker_id'] for x in c.execute('SELECT worker_id FROM receipts WHERE month=?',(request.args.get('month','2026-09'),)).fetchall()}
 for w in rows:w['paid']=w['id'] in done;w['masked']='****'+w['iqama'][-4:]
 return page('''<h2>قائمة العمال والتسليم</h2><p class="notice">الإثبات بالتوقيع هنا سجل إداري داخلي فقط. SMS/واتساب والفيديو غير متصلين بعد. لا تستخدمه بديلًا عن الالتزام بحماية الأجور.</p><div class="grid"><div class="card">العمال المتاحون<div class="metric">{{rows|length}}</div></div><div class="card">تم توثيق استلامهم للشهر<div class="metric">{{rows|selectattr('paid')|list|length}}</div></div><div class="card">لم يوثق الاستلام<div class="metric">{{rows|rejectattr('paid')|list|length}}</div></div></div><div class="card"><form method="get" class="actions"><label>الشهر <input type="month" name="month" value="{{month}}"></label><button>عرض</button><input id="search" oninput="filterRows()" placeholder="بحث بالاسم أو الفرع أو الإقامة"></form><div class="scroll"><table id="workers"><tr><th>الاسم</th><th>الإقامة (مخفية)</th><th>الفرع</th><th>المهنة</th><th>الراتب</th><th>المشرف</th><th>الحالة</th><th>الإجراء</th></tr>{% for w in rows %}<tr><td>{{w.name}}</td><td>{{w.masked}}</td><td>{{w.store}}</td><td>{{w.position}}</td><td>{{'%.2f'|format(w.salary)}}</td><td>{{w.supervisor or 'غير مخصص'}}</td><td>{{'موثق' if w.paid else 'لم يوثق'}}</td><td>{% if not w.paid %}<a href="/receipt/{{w.id}}?month={{month}}">تسليم</a>{% endif %}{% if isadmin %} | <a href="/workers/{{w.id}}/edit">تعديل</a>{% endif %}</td></tr>{% endfor %}</table></div></div><script>function filterRows(){let q=document.getElementById('search').value.toLowerCase();document.querySelectorAll('#workers tr').forEach((r,i)=>{if(i)r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}</script>''',rows=rows,month=request.args.get('month','2026-09'),isadmin=session['role']=='admin')
@app.route('/users',methods=['GET','POST'])
@admin
def users():
 if request.method=='POST':
  csrf();action=request.form.get('action');uid=request.form.get('uid',type=int)
  with db() as c:
   if action=='add':
    username=request.form.get('username','').strip();password=request.form.get('password','');role=request.form.get('role')
    if len(password)<12 or role not in ('supervisor','courier','rent_agent') or not username:abort(400)
    
    cur=c.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(username,generate_password_hash(password),'courier' if role=='rent_agent' else role))
    if role=='rent_agent':c.execute('INSERT INTO rent_agents(user_id) VALUES(?)',(cur.lastrowid,))
    log(c,'add_user',username)
   elif action=='disable':
    if uid==session['uid']:abort(400)
    c.execute('UPDATE users SET active=0 WHERE id=? AND role<>"admin"',(uid,));log(c,'disable_user',str(uid))
   elif action=='reset':
    password=request.form.get('password','')
    if len(password)<12:abort(400)
    c.execute('UPDATE users SET password=? WHERE id=? AND role<>"admin"',(generate_password_hash(password),uid));log(c,'reset_password',str(uid))
  return redirect('/users')
 with db() as c:rows=c.execute('SELECT id,username,role,active FROM users ORDER BY id').fetchall()
 return page('''<h2>إدارة المشرفين والمندوبين — المدير فقط</h2><div class="card"><h3>إضافة حساب</h3><form method="post">{{csrf|safe}}<input type="hidden" name="action" value="add"><input name="username" placeholder="اسم المستخدم" required><input name="password" type="password" minlength="12" placeholder="كلمة مرور 12 حرفًا على الأقل" required><select name="role"><option value="supervisor">مشرف</option><option value="courier">مندوب</option><option value="rent_agent">مسؤول الإيجارات</option></select><button>إضافة</button></form></div><div class="card scroll"><table><tr><th>المستخدم</th><th>الدور</th><th>الحالة</th><th>إجراء</th></tr>{% for u in rows %}<tr><td>{{u.username}}</td><td>{{u.role}}</td><td>{{'نشط' if u.active else 'معطل'}}</td><td>{% if u.role!='admin' and u.active %}<form method="post" style="display:inline">{{csrf|safe}}<input type="hidden" name="action" value="disable"><input type="hidden" name="uid" value="{{u.id}}"><button onclick="return confirm('تعطيل الحساب؟')">تعطيل</button></form><form method="post" style="display:inline">{{csrf|safe}}<input type="hidden" name="action" value="reset"><input type="hidden" name="uid" value="{{u.id}}"><input name="password" type="password" minlength="12" placeholder="كلمة مرور جديدة" required><button>تغيير كلمة المرور</button></form>{% endif %}</td></tr>{% endfor %}</table></div>''',rows=rows)
@app.route('/assign',methods=['GET','POST'])
@admin
def assign():
 if request.method=='POST':
  csrf();action=request.form.get('action');uid=request.form.get('user_id',type=int)
  with db() as c:
   if not c.execute('SELECT 1 FROM users WHERE id=? AND active=1 AND role<>"admin"',(uid,)).fetchone():abort(400)
   if action=='store':
    store=request.form.get('store','').strip()
    if not store:abort(400)
    c.execute('INSERT OR IGNORE INTO assignments(user_id,store) VALUES(?,?)',(uid,store));log(c,'assign_store',f'{uid}:{store}')
   elif action=='remove_store':
    store=request.form.get('store','');c.execute('DELETE FROM assignments WHERE user_id=? AND store=?',(uid,store));log(c,'remove_store',f'{uid}:{store}')
   elif action=='worker':
    wid=request.form.get('worker_id',type=int);c.execute('UPDATE workers SET supervisor_id=? WHERE id=?',(uid,wid));log(c,'assign_worker',f'{wid}:{uid}')
  return redirect('/assign')
 with db() as c:
  users=c.execute('SELECT id,username FROM users WHERE active=1 AND role<>"admin"').fetchall();stores=c.execute('SELECT DISTINCT store FROM workers ORDER BY store').fetchall();assignments=c.execute('SELECT a.*,u.username FROM assignments a JOIN users u ON u.id=a.user_id ORDER BY a.store').fetchall();workers=c.execute('SELECT id,name,store FROM workers WHERE active=1 ORDER BY store,name').fetchall()
 return page('''<h2>توزيع الفروع والعمال — المدير فقط</h2><div class="grid"><div class="card"><h3>إسناد فرع لمشرف / مندوب</h3><form method="post">{{csrf|safe}}<input type="hidden" name="action" value="store"><select name="store">{% for s in stores %}<option>{{s.store}}</option>{% endfor %}</select><select name="user_id">{% for u in users %}<option value="{{u.id}}">{{u.username}}</option>{% endfor %}</select><button>إسناد الفرع</button></form></div><div class="card"><h3>نقل عامل لمشرف</h3><form method="post">{{csrf|safe}}<input type="hidden" name="action" value="worker"><select name="worker_id">{% for w in workers %}<option value="{{w.id}}">{{w.name}} — {{w.store}}</option>{% endfor %}</select><select name="user_id">{% for u in users %}<option value="{{u.id}}">{{u.username}}</option>{% endfor %}</select><button>نقل العامل</button></form></div></div><div class="card"><h3>صلاحيات الفروع الحالية</h3><div class="scroll"><table><tr><th>الفرع</th><th>المستخدم</th><th>الإجراء</th></tr>{% for a in assignments %}<tr><td>{{a.store}}</td><td>{{a.username}}</td><td><form method="post">{{csrf|safe}}<input type="hidden" name="action" value="remove_store"><input type="hidden" name="user_id" value="{{a.user_id}}"><input type="hidden" name="store" value="{{a.store}}"><button>إلغاء الإسناد</button></form></td></tr>{% endfor %}</table></div></div>''',users=users,stores=stores,assignments=assignments,workers=workers)
@app.route('/workers/new',methods=['GET','POST'])
@app.route('/workers/<int:wid>/edit',methods=['GET','POST'])
@admin
def worker_edit(wid=None):
 with db() as c:
  w=c.execute('SELECT * FROM workers WHERE id=?',(wid,)).fetchone() if wid else None
  if wid and not w:abort(404)
  if request.method=='POST':
   csrf();name=request.form.get('name','').strip();iqama=request.form.get('iqama','').strip();store=request.form.get('store','').strip();position=request.form.get('position','').strip();salary=request.form.get('salary',type=float)
   if not name or not iqama or not store or salary is None or salary<0:abort(400)
   if wid:
    c.execute('UPDATE workers SET name=?,iqama=?,store=?,position=?,salary=?,active=? WHERE id=?',(name,iqama,store,position,salary,int(request.form.get('active','1')),wid));log(c,'edit_worker',str(wid))
   else:
    c.execute('INSERT INTO workers(name,iqama,store,position,salary) VALUES(?,?,?,?,?)',(name,iqama,store,position,salary));log(c,'add_worker',iqama[-4:])
   return redirect('/')
 return page('''<div class="card"><h2>{{'تعديل العامل' if w else 'إضافة عامل'}}</h2><form method="post">{{csrf|safe}}<p><label>الاسم <input required name="name" value="{{w.name if w else ''}}"></label><label>رقم الإقامة <input required name="iqama" value="{{w.iqama if w else ''}}"></label></p><p><label>الفرع <input required name="store" value="{{w.store if w else ''}}"></label><label>المهنة <input name="position" value="{{w.position if w else ''}}"></label><label>الراتب <input required type="number" step=".01" min="0" name="salary" value="{{w.salary if w else 0}}"></label></p>{% if w %}<label>الحالة <select name="active"><option value="1" {{'selected' if w.active else ''}}>نشط</option><option value="0" {{'selected' if not w.active else ''}}>مؤرشف</option></select></label>{% endif %}<button>حفظ</button></form></div>''',w=w)
@app.route('/receipt/<int:wid>',methods=['GET','POST'])
@logged
def receipt(wid):
 with db() as c:
  w=c.execute('SELECT * FROM workers WHERE id=? AND active=1',(wid,)).fetchone()
  if not w:abort(404)
  if not allowed(c,w):abort(403)
  month=request.values.get('month','2026-09')
  if request.method=='POST':
   csrf();amount=request.form.get('amount',type=float);method=request.form.get('method');signature=request.form.get('signature','');notes=request.form.get('notes','')[:2000]
   if amount is None or amount<=0 or method!='signature' or not signature.startswith('data:image/png;base64,') or len(signature)>180000:abort(400,'Signature required; SMS/WhatsApp not yet connected')
   try:base64.b64decode(signature.split(',',1)[1],validate=True)
   except Exception:abort(400)
   try:
    c.execute('INSERT INTO receipts(worker_id,month,amount,method,signature,notes,operator_id,created) VALUES(?,?,?,?,?,?,?,?)',(wid,month,amount,method,signature,notes,session['uid'],now()));log(c,'record_receipt',f'worker={wid},month={month},amount={amount}')
   except sqlite3.IntegrityError:abort(409,'Already recorded for this worker/month')
   flash('تم تسجيل إقرار الاستلام الداخلي. لا يُعد توثيقًا نظاميًا مستقلًا لصرف النقد.');return redirect('/')
 return page('''<div class="card" style="max-width:750px"><h2>محضر استلام راتب — توقيع العامل</h2><p><b>{{w.name}}</b> | إقامة تنتهي بـ {{w.iqama[-4:]}} | فرع {{w.store}} | راتب {{w.salary}} ريال</p><p class="notice">يوقّع العامل بنفسه بعد استلام المبلغ الفعلي، مع التأكد من هويته. التوقيع المصوّر ليس توقيعًا رقميًا معتمدًا تلقائيًا.</p><form method="post" onsubmit="return saveSig()">{{csrf|safe}}<input type="hidden" name="month" value="{{month}}"><input type="hidden" name="method" value="signature"><input type="hidden" id="signature" name="signature"><p><label>المبلغ المسلّم <input type="number" min="0.01" step=".01" name="amount" required value="{{w.salary}}"></label></p><p>أقر أنا العامل المذكور أعلاه باستلام المبلغ الظاهر نقدًا عن شهر {{month}}.</p><canvas id="pad" width="700" height="180"></canvas><p><button type="button" onclick="ctx.clearRect(0,0,pad.width,pad.height);drawn=false">مسح التوقيع</button></p><p><textarea name="notes" rows="3" style="width:100%" placeholder="ملاحظات التسليم"></textarea></p><button>تسجيل المحضر</button></form></div><script>let pad=document.getElementById('pad'),ctx=pad.getContext('2d'),down=false,drawn=false;ctx.lineWidth=2.5;function pos(e){let r=pad.getBoundingClientRect();return [(e.clientX-r.left)*pad.width/r.width,(e.clientY-r.top)*pad.height/r.height]}pad.addEventListener('pointerdown',e=>{down=true;pad.setPointerCapture(e.pointerId);let p=pos(e);ctx.beginPath();ctx.moveTo(...p)});pad.addEventListener('pointermove',e=>{if(!down)return;let p=pos(e);ctx.lineTo(...p);ctx.stroke();drawn=true});pad.addEventListener('pointerup',()=>down=false);function saveSig(){if(!drawn){alert('يلزم توقيع العامل');return false}document.getElementById('signature').value=pad.toDataURL('image/png');return confirm('هل تم تسليم المبلغ فعليًا للعامل؟')}</script>''',w=w,month=month)
@app.route('/reports')
@logged
def reports():
 with db() as c:
  rows=c.execute('SELECT r.*,w.name,w.store,w.iqama,u.username operator FROM receipts r JOIN workers w ON w.id=r.worker_id JOIN users u ON u.id=r.operator_id ORDER BY r.created DESC').fetchall()
  rows=[dict(x) for x in rows if session['role']=='admin' or x['operator_id']==session['uid']]
 if request.args.get('format')=='csv':
  output=io.StringIO();writer=csv.writer(output);writer.writerow(['رقم العملية','العامل','الفرع','الشهر','المبلغ','المشرف','التاريخ','الملاحظات'])
  for x in rows:writer.writerow([x['id'],x['name'],x['store'],x['month'],x['amount'],x['operator'],x['created'],x['notes']])
  return Response('\ufeff'+output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=receipts.csv'})
 return page('''<h2>تقرير الاستلام</h2><div class="grid"><div class="card">العمليات<div class="metric">{{rows|length}}</div></div><div class="card">إجمالي الموثق<div class="metric">{{'%.2f'|format(total)}} ر.س</div></div></div><p><a class="btn" href="/reports?format=csv">تصدير CSV</a></p><div class="card scroll"><table><tr><th>رقم</th><th>العامل</th><th>الفرع</th><th>الشهر</th><th>المبلغ</th><th>المسؤول</th><th>التاريخ</th><th>الملاحظات</th></tr>{% for r in rows %}<tr><td>{{r.id}}</td><td>{{r.name}}</td><td>{{r.store}}</td><td>{{r.month}}</td><td>{{r.amount}}</td><td>{{r.operator}}</td><td>{{r.created}}</td><td>{{r.notes}}</td></tr>{% endfor %}</table></div>''',rows=rows,total=sum(x['amount'] for x in rows))
@app.route('/audit')
@admin
def audit():
 with db() as c:rows=c.execute('SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 500').fetchall()
 return page('''<h2>سجل التدقيق</h2><div class="card scroll"><table><tr><th>الوقت</th><th>المستخدم</th><th>الإجراء</th><th>التفاصيل</th></tr>{% for r in rows %}<tr><td>{{r.created}}</td><td>{{r.username}}</td><td>{{r.action}}</td><td>{{r.details}}</td></tr>{% endfor %}</table></div>''',rows=rows)
from rentals import install as install_rentals
install_rentals(app,db,page,logged,admin,csrf,log,now)
if __name__=='__main__':
 init();app.run(host='127.0.0.1',port=int(os.environ.get('PORT',5000)),debug=False)
