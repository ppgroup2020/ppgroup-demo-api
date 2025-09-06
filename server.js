// Simplified from the previous full API for brevity in this build
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const DB_PATH = path.join(__dirname, 'ppgroup.db');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const JWT_SECRET = process.env.JWT_SECRET || 'muda_isto_em_producao';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(UPLOAD_DIR));

const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'tecnico',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS appointments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, nome TEXT, contacto TEXT, servico TEXT, data TEXT, hora TEXT, notas TEXT,
    estado TEXT DEFAULT 'pendente', client_id INTEGER, criadoEm TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS quotes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, nome TEXT, contacto TEXT, item TEXT, descricao TEXT, valor_est TEXT,
    estado TEXT DEFAULT 'novo', client_id INTEGER, criadoEm TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS checkups(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, appointment_id INTEGER, data_check TEXT, estado_veiculo TEXT, observacoes TEXT,
    client_id INTEGER, criadoEm TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS checkup_photos(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkup_id INTEGER, url TEXT, filename TEXT, uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Auto-seed: cria utilizadores de teste se a tabela estiver vazia
db.get('SELECT COUNT(*) AS c FROM users', [], (e, row) => {
  if (row && row.c === 0) {
    const bcrypt = require('bcryptjs');
    const h = bcrypt.hashSync('senha123', 8);
    const ins = db.prepare('INSERT INTO users(name,email,password,role) VALUES (?,?,?,?)');
    ins.run('Ana Admin','admin@ppgroup.com',h,'admin');
    ins.run('Guilherme Gestor','gestor@ppgroup.com',h,'gestor');
    ins.run('Tiago Tecnico','tecnico@ppgroup.com',h,'tecnico');
    ins.run('Clara Cliente','cliente@ppgroup.com',h,'cliente');
    ins.finalize(() => console.log('✅ Auto-seed concluído'));
  }
});


function tokenFor(u){ return jwt.sign({id:u.id,email:u.email,name:u.name,role:u.role}, JWT_SECRET, {expiresIn:'7d'}); }
function auth(req,res,next){
  const h=req.headers.authorization||''; const t=h.split(' ')[1];
  if(!t) return res.status(401).json({error:'Sem token'});
  try{ req.user=jwt.verify(t, JWT_SECRET); next(); }catch(e){ return res.status(401).json({error:'Token inválido'}); }
}

app.get('/api/health', (req,res)=> res.json({ok:true,name:'PP Group API'}));

app.post('/api/register', (req,res)=>{
  const {name,email,password,role} = req.body;
  if(!email||!password) return res.status(400).json({error:'Email e password obrigatórios'});
  const hash=bcrypt.hashSync(password,8);
  // first user keeps requested role; others default tecnico if not provided
  db.get('SELECT COUNT(*) c FROM users',[],(e,row)=>{
    const r = (row && row.c===0) ? (role||'admin') : (role||'tecnico');
    const stmt = db.prepare('INSERT INTO users(name,email,password,role) VALUES (?,?,?,?)');
    stmt.run(name||'',email,hash,r,function(err){
      if(err) return res.status(400).json({error:'Email já registado'});
      const user={id:this.lastID,name:name||'',email,role:r};
      res.json({user,token:tokenFor(user)});
    });
  });
});

app.post('/api/login', (req,res)=>{
  const {email,password}=req.body;
  if(!email||!password) return res.status(400).json({error:'Email e password obrigatórios'});
  db.get('SELECT * FROM users WHERE email=?',[email],(e,row)=>{
    if(!row) return res.status(401).json({error:'Credenciais inválidas'});
    if(!bcrypt.compareSync(password,row.password)) return res.status(401).json({error:'Credenciais inválidas'});
    const user={id:row.id,name:row.name,email:row.email,role:row.role};
    res.json({user,token:tokenFor(user)});
  });
});

// Appointments (admin/gestor vê tudo, cliente só os dele, tecnico só os dele)
app.get('/api/appointments', auth, (req,res)=>{
  const r=req.user.role;
  if(r==='admin'||r==='gestor'){
    db.all('SELECT * FROM appointments ORDER BY data,hora',[],(e,rows)=> res.json(rows||[]));
  } else if(r==='cliente'){
    db.all('SELECT * FROM appointments WHERE client_id=? ORDER BY data,hora',[req.user.id],(e,rows)=> res.json(rows||[]));
  } else {
    db.all('SELECT * FROM appointments WHERE user_id=? ORDER BY data,hora',[req.user.id],(e,rows)=> res.json(rows||[]));
  }
});

// Quotes
app.get('/api/quotes', auth, (req,res)=>{
  const r=req.user.role;
  if(r==='admin'||r==='gestor'){
    db.all('SELECT * FROM quotes ORDER BY criadoEm DESC',[],(e,rows)=> res.json(rows||[]));
  } else if(r==='cliente'){
    db.all('SELECT * FROM quotes WHERE client_id=? ORDER BY criadoEm DESC',[req.user.id],(e,rows)=> res.json(rows||[]));
  } else {
    res.json([]);
  }
});

// Checkups
app.get('/api/checkups', auth, (req,res)=>{
  const r=req.user.role;
  if(r==='admin'||r==='gestor'){
    db.all('SELECT * FROM checkups ORDER BY criadoEm DESC',[],(e,rows)=> res.json(rows||[]));
  } else if(r==='cliente'){
    db.all('SELECT * FROM checkups WHERE client_id=? ORDER BY criadoEm DESC',[req.user.id],(e,rows)=> res.json(rows||[]));
  } else {
    db.all('SELECT * FROM checkups WHERE user_id=? ORDER BY criadoEm DESC',[req.user.id],(e,rows)=> res.json(rows||[]));
  }
});

// photos upload (tecnico/admin)
const storage = multer.diskStorage({
  destination: (req,file,cb)=>{ const dir=path.join(UPLOAD_DIR,'checkups',String(req.params.id)); fs.mkdirSync(dir,{recursive:true}); cb(null,dir); },
  filename: (req,file,cb)=> cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9.\-_]/g,'_'))
});
const upload = multer({ storage, limits:{fileSize:10*1024*1024} });
app.post('/api/checkups/:id/photos', auth, upload.array('photos',10), (req,res)=>{
  const files=req.files||[];
  const ins=db.prepare('INSERT INTO checkup_photos(checkup_id,url,filename) VALUES (?,?,?)');
  files.forEach(f=> ins.run(req.params.id, '/uploads/checkups/'+req.params.id+'/'+f.filename, f.originalname));
  ins.finalize(()=> res.json({ok:true,count:files.length}));
});
app.get('/api/checkups/:id/photos', auth, (req,res)=>{
  db.all('SELECT id,url,filename,uploaded_at FROM checkup_photos WHERE checkup_id=? ORDER BY id DESC',[req.params.id],(e,rows)=> res.json(rows||[]));
});

app.use('/', express.static(path.join(__dirname,'..','client')));
app.get('/', (req,res) => res.type('text').send('PP Group API OK'));

app.listen(PORT, ()=> console.log('PP Group API a correr na porta', PORT));
