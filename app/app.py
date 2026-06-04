"""
VulnShop - Application e-commerce volontairement vulnérable
TP Sécurité DevSecOps - Master 1 Cybersécurité SECUA ÉCOLE IT
ATTENTION : NE PAS UTILISER EN PRODUCTION
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import subprocess
import bcrypt
import os
import yaml
import requests
import pickle
import base64

app = Flask(__name__)

# VULN-01 : Clé secrète hardcodée (Bandit B105)
app.secret_key = "super_secret_key_1234"
SECRET_API_KEY = "sk-prod-hardcoded-key-abc123"
DB_PASSWORD = "admin123"

# VULN-02 : Base de données SQLite initialisée sans paramètres
DATABASE = "vulnshop.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    """)
    # CORRIGÉ (B324) : hachage bcrypt (salé, lent) au lieu de MD5
    pw_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin')", (pw_hash,))
    conn.execute("INSERT OR IGNORE INTO products VALUES (1, 'Laptop', 999.99, 'Un super laptop')")
    conn.execute("INSERT OR IGNORE INTO products VALUES (2, 'Phone', 499.99, 'Un smartphone')")
    conn.commit()
    conn.close()


# VULN-04 : Injection SQL directe (Bandit B608)
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    # CORRIGÉ (B608) : requête paramétrée — plus d'injection SQL
    cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    # CORRIGÉ (B324) : vérification du mot de passe via bcrypt
    if user and bcrypt.checkpw(password.encode(), user[2].encode()):
        return jsonify({"status": "ok", "user": username, "role": user[3]})
    return jsonify({"status": "error", "message": "Identifiants invalides"}), 401


# VULN-05 : XSS reflété (aucune sanitisation)
@app.route("/search")
def search():
    term = request.args.get("q", "")
    # Rendu direct du paramètre utilisateur dans le template
    template = f"""
    <html><body>
    <h1>Résultats pour : {term}</h1>
    <p>Aucun résultat.</p>
    </body></html>
    """
    return render_template_string(template)


# VULN-06 : Injection de commande OS (Bandit B602)
@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # CORRIGÉ (B602) : arguments en liste, shell=False — plus d'injection de commande
    result = subprocess.check_output(["ping", "-c", "1", host])
    return result.decode()


# VULN-07 : Path traversal
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # Aucune validation du chemin
    filepath = os.path.join("/var/www/uploads", filename)
    with open(filepath, "rb") as f:
        return f.read()


# VULN-08 : Désérialisation non sécurisée (Bandit B301)
@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.form.get("session_data", "")
    # Pickle sur une entrée utilisateur — RCE possible
    obj = pickle.loads(base64.b64decode(data))
    return jsonify({"loaded": str(obj)})


# VULN-09 : Requête SSRF
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # Aucune validation de l'URL cible
    response = requests.get(url, timeout=5)
    return response.text


# VULN-10 : Chargement YAML non sécurisé (Bandit B506)
@app.route("/config", methods=["POST"])
def load_config():
    config_data = request.form.get("config", "")
    # CORRIGÉ (B506) : yaml.safe_load() interdit l'instanciation d'objets arbitraires
    config = yaml.safe_load(config_data)
    return jsonify(config)


# VULN-11 : Vérification SSL désactivée
@app.route("/check_site")
def check_site():
    url = request.args.get("url", "https://example.com")
    # CORRIGÉ (B501) : verify=True active la vérification des certificats TLS
    r = requests.get(url, verify=True)
    return jsonify({"status": r.status_code})


# VULN-12 : Divulgation d'informations système
@app.route("/debug")
def debug():
    return jsonify({
        "env": dict(os.environ),
        "cwd": os.getcwd(),
        "files": os.listdir("."),
        "secret": SECRET_API_KEY,
    })


if __name__ == "__main__":
    init_db()
    # CORRIGÉ (B201) : debug=False en production — évite l'exposition du debugger Werkzeug
    app.run(debug=False, host="0.0.0.0", port=5000)
