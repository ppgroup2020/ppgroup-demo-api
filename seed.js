// seed.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname,'ppgroup.db'));
function run(sql,p=[]){ return new Promise(r=> db.run(sql,p,()=>r())); }
(async()=>{
  await run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,email TEXT UNIQUE,password TEXT,role TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)');
  await run('CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,nome TEXT,contacto TEXT,servico TEXT,data TEXT,hora TEXT,notas TEXT,estado TEXT DEFAULT "pendente",client_id INTEGER,criadoEm TEXT DEFAULT CURRENT_TIMESTAMP)');
  await run('CREATE TABLE IF NOT EXISTS quotes(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,nome TEXT,contacto TEXT,item TEXT,descricao TEXT,valor_est TEXT,estado TEXT DEFAULT "novo",client_id INTEGER,criadoEm TEXT DEFAULT CURRENT_TIMESTAMP)');
  await run('CREATE TABLE IF NOT EXISTS checkups(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,appointment_id INTEGER,data_check TEXT,estado_veiculo TEXT,observacoes TEXT,client_id INTEGER,criadoEm TEXT DEFAULT CURRENT_TIMESTAMP)');
  const hash=bcrypt.hashSync('senha123',8);
  const users=[['Ana Admin','admin@ppgroup.com',hash,'admin'],['Guilherme Gestor','gestor@ppgroup.com',hash,'gestor'],['Tiago Tecnico','tecnico@ppgroup.com',hash,'tecnico'],['Clara Cliente','cliente@ppgroup.com',hash,'cliente']];
  for(const u of users){ await run('INSERT OR IGNORE INTO users(name,email,password,role) VALUES (?,?,?,?)',u); }
  await run('INSERT INTO appointments(user_id,nome,contacto,servico,data,hora,notas,estado,client_id) VALUES (?,?,?,?,?,?,?,?,?)',[2,'Clara Cliente','912345678','Revisão Geral','2025-09-10','10:00','Primeira revisão','pendente',4]);
  await run('INSERT INTO quotes(user_id,nome,contacto,item,descricao,valor_est,estado,client_id) VALUES (?,?,?,?,?,?,?,?)',[2,'Clara Cliente','cliente@ppgroup.com','Revisão Geral','Inclui filtros e óleo','350','em análise',4]);
  console.log('Seed concluído.');
  process.exit(0);
})();
