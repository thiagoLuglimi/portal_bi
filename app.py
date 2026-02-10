from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma-chave-muito-segura' # Mude isso depois

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DB = 'database.db'

def conectar():
    return sqlite3.connect(DB)

# ---------- BANCO DE DADOS ----------
def criar_tabelas():
    con = conectar()
    cur = con.cursor()
    # Tabela de Usuários
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            usuario TEXT UNIQUE,
            senha TEXT,
            departamento TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # Tabela de Dashboards
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dashboards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT,
            link TEXT,
            departamento TEXT
        )
    """)
    
    # Criar um admin padrão se não existir (Usuário: admin / Senha: 123)
    cur.execute("SELECT * FROM usuarios WHERE usuario = 'admin'")
    if not cur.fetchone():
        senha_hash = generate_password_hash('123')
        cur.execute("INSERT INTO usuarios (nome, usuario, senha, departamento, is_admin) VALUES (?,?,?,?,?)",
                    ('Administrador', 'admin', senha_hash, 'TI', 1))
    
    con.commit()
    con.close()

criar_tabelas()

# ---------- GESTÃO DE LOGIN ----------
class User(UserMixin):
    def __init__(self, id, nome, usuario, departamento, is_admin):
        self.id = id
        self.nome = nome
        self.usuario = usuario
        self.departamento = departamento
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    con = conectar()
    res = con.execute("SELECT id, nome, usuario, departamento, is_admin FROM usuarios WHERE id=?", (user_id,)).fetchone()
    con.close()
    if res:
        return User(*res)
    return None

# ---------- ROTAS ----------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_input = request.form.get('usuario')
        senha_input = request.form.get('senha')
        
        con = conectar()
        res = con.execute("SELECT id, nome, usuario, senha, departamento, is_admin FROM usuarios WHERE usuario=?", (user_input,)).fetchone()
        con.close()
        
        if res and check_password_hash(res[3], senha_input):
            user_obj = User(res[0], res[1], res[2], res[4], res[5])
            login_user(user_obj)
            return redirect(url_for('index'))
        
        flash('Usuário ou senha inválidos')
    return render_template('login.html')

@app.route('/')
@login_required
def index():
    con = conectar()
    # O usuário comum só vê o que é do departamento dele
    if current_user.is_admin:
        dashs = con.execute("SELECT * FROM dashboards").fetchall()
    else:
        dashs = con.execute("SELECT * FROM dashboards WHERE departamento=?", (current_user.departamento,)).fetchone()
    con.close()
    return render_template('index.html', dashs=dashs)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return "Acesso negado", 403
    
    con = conectar()
    if request.method == 'POST':
        # Cadastro de Usuário
        if 'add_user' in request.form:
            nome = request.form.get('nome')
            user = request.form.get('usuario')
            senha = generate_password_hash(request.form.get('senha'))
            dept = request.form.get('departamento')
            con.execute("INSERT INTO usuarios (nome, usuario, senha, departamento) VALUES (?,?,?,?)", (nome, user, senha, dept))
        
        # Cadastro de Dashboard
        elif 'add_dash' in request.form:
            titulo = request.form.get('titulo')
            link = request.form.get('link')
            dept = request.form.get('departamento')
            con.execute("INSERT INTO dashboards (titulo, link, departamento) VALUES (?,?,?)", (titulo, link, dept))
        
        con.commit()
    
    usuarios = con.execute("SELECT * FROM usuarios").fetchall()
    dashs = con.execute("SELECT * FROM dashboards").fetchall()
    con.close()
    return render_template('admin.html', usuarios=usuarios, dashs=dashs)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)