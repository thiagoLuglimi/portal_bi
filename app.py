from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'portal_bi_secret_123456'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DB_NAME = 'database.db'

# ---------------------------
# BANCO
# ---------------------------
def conectar():
    return sqlite3.connect(
        DB_NAME,
        timeout=30,
        check_same_thread=False
    )

def init_db():
    con = conectar()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS departamentos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT UNIQUE NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        senha TEXT NOT NULL,
        departamento_id INTEGER,
        role TEXT DEFAULT 'user'
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS dashboards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT,
        url TEXT,
        departamento_id INTEGER,
        pasta_id INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS pastas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT,
        departamento_id INTEGER
    )
    """)

    # criar admin se não existir
    cur.execute("SELECT * FROM usuarios WHERE username='admin'")
    if not cur.fetchone():
        cur.execute("""
        INSERT INTO usuarios (username, senha, departamento_id, role)
        VALUES (?, ?, ?, ?)
        """, ('admin', generate_password_hash('admin123'), 1, 'admin'))

    con.commit()
    con.close()

# ---------------------------
# LOGIN
# ---------------------------
class User(UserMixin):
    def __init__(self, id, username, departamento_id, role):
        self.id = id
        self.username = username
        self.departamento_id = departamento_id
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    con = conectar()
    cur = con.cursor()
    cur.execute("SELECT id, username, departamento_id, role FROM usuarios WHERE id = ?", (user_id,))
    user = cur.fetchone()
    con.close()
    return User(*user) if user else None

# ---------------------------
# LOGIN
# ---------------------------
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        senha = request.form['senha']

        con = conectar()
        cur = con.cursor()
        cur.execute("SELECT id, username, senha, departamento_id, role FROM usuarios WHERE username = ?", (user,))
        row = cur.fetchone()
        con.close()

        if row and check_password_hash(row[2], senha):
            user_obj = User(row[0], row[1], row[3], row[4])
            login_user(user_obj)

            # 🔥 ADMIN VAI PARA /admin
            if user_obj.role == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('index'))

    return render_template('login.html')

# ---------------------------
# INDEX (USUÁRIO)
# ---------------------------
@app.route('/index')
@login_required
def index():
    con = conectar()
    cur = con.cursor()

    cur.execute("""
    SELECT p.nome, d.nome, d.url
    FROM dashboards d
    LEFT JOIN pastas p ON d.pasta_id = p.id
    WHERE d.departamento_id = ?
    """, (current_user.departamento_id,))

    dados = cur.fetchall()
    con.close()

    estrutura = {}

    for pasta, nome, url in dados:
        pasta = pasta or "Sem Pasta"
        if pasta not in estrutura:
            estrutura[pasta] = []
        estrutura[pasta].append((nome, url))

    return render_template('index.html', estrutura=estrutura)

# ---------------------------
# ADMIN
# ---------------------------
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    con = conectar()
    cur = con.cursor()

    if request.method == 'POST':

        if 'add_dept' in request.form:
            cur.execute("INSERT INTO departamentos (nome) VALUES (?)",
                        (request.form['departamento'],))

        elif 'add_user' in request.form:
            cur.execute("""
            INSERT INTO usuarios (username, senha, departamento_id, role)
            VALUES (?, ?, ?, 'user')
            """, (
                request.form['username'],
                generate_password_hash(request.form['senha']),
                request.form['departamento_id']
            ))

        elif 'add_bi' in request.form:
            cur.execute("""
            INSERT INTO dashboards (nome, url, departamento_id, pasta_id)
            VALUES (?, ?, ?, ?)
            """, (
                request.form['nome'],
                request.form['url'],
                request.form['departamento_id'],
                request.form.get('pasta_id')
            ))

        elif 'add_pasta' in request.form:
            cur.execute("""
            INSERT INTO pastas (nome, departamento_id)
            VALUES (?, ?)
            """, (
                request.form['nome_pasta'],
                request.form['departamento_id']
            ))

        con.commit()

    cur.execute("SELECT * FROM departamentos")
    departamentos = cur.fetchall()

    cur.execute("SELECT * FROM usuarios")
    usuarios = cur.fetchall()

    cur.execute("SELECT * FROM dashboards")
    dashboards = cur.fetchall()

    cur.execute("SELECT * FROM pastas")
    pastas = cur.fetchall()

    con.close()

    return render_template(
        'admin.html',
        departamentos=departamentos,
        usuarios=usuarios,
        dashboards=dashboards,
        pastas=pastas
    )

# ---------------------------
# LOGOUT
# ---------------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------------------

# ---------------------------
# EXCLUSÕES
# ---------------------------

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    con = conectar()
    cur = con.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = ?", (id,))
    con.commit()
    con.close()

    return redirect(url_for('admin'))


@app.route('/delete_bi/<int:id>')
@login_required
def delete_bi(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    con = conectar()
    cur = con.cursor()
    cur.execute("DELETE FROM dashboards WHERE id = ?", (id,))
    con.commit()
    con.close()

    return redirect(url_for('admin'))


@app.route('/delete_dept/<int:id>')
@login_required
def delete_dept(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    con = conectar()
    cur = con.cursor()
    cur.execute("DELETE FROM departamentos WHERE id = ?", (id,))
    con.commit()
    con.close()

    return redirect(url_for('admin'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001)