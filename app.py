from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import bleach
import requests
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import json
import os
import re
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ── CONFIGURACION DE SEGURIDAD ──
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "cambia_esto_por_algo_muy_largo_y_random")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False  # cambiar a True en produccion con HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutos
app.config["WTF_CSRF_ENABLED"] = True

# ── INICIALIZAR EXTENSIONES ──
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Debes iniciar sesion para acceder"

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ── CONFIGURACION EMAIL ──
email_origen = os.getenv("EMAIL_ORIGEN")
email_destino = os.getenv("EMAIL_DESTINO")
email_password = os.getenv("EMAIL_PASSWORD")
admin_password = os.getenv("ADMIN_PASSWORD")

# ── ARCHIVO DE USUARIOS ──
USUARIOS_FILE = "usuarios.json"

def cargar_usuarios():
    if not os.path.exists(USUARIOS_FILE):
        return {}
    with open(USUARIOS_FILE, "r") as f:
        return json.load(f)

def guardar_usuarios(usuarios):
    with open(USUARIOS_FILE, "w") as f:
        json.dump(usuarios, f, indent=4)

# ── MODELO DE USUARIO ──
class Usuario(UserMixin):
    def __init__(self, email, datos):
        self.id = email
        self.email = email
        self.nombre = datos.get("nombre", "")
        self.es_admin = datos.get("admin", False)

@login_manager.user_loader
def cargar_usuario(email):
    usuarios = cargar_usuarios()
    if email in usuarios:
        return Usuario(email, usuarios[email])
    return None

# ── HEADERS DE SEGURIDAD EN CADA RESPUESTA ──
@app.after_request
def agregar_headers_seguridad(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# ── VALIDACIONES ──
def validar_email(email):
    patron = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(patron, email) is not None

def validar_password(password):
    if len(password) < 8:
        return False, "Minimo 8 caracteres"
    if not re.search(r'[A-Z]', password):
        return False, "Debe tener al menos una mayuscula"
    if not re.search(r'[0-9]', password):
        return False, "Debe tener al menos un numero"
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Debe tener al menos un simbolo"
    return True, "OK"

def sanitizar(texto):
    return bleach.clean(texto, tags=[], strip=True)

# ── EMAIL ──
def enviar_email(asunto, cuerpo):
    try:
        mensaje = MIMEText(cuerpo)
        mensaje["Subject"] = asunto
        mensaje["From"] = email_origen
        mensaje["To"] = email_destino
        servidor = smtplib.SMTP("smtp.gmail.com", 587)
        servidor.starttls()
        servidor.login(email_origen, email_password)
        servidor.sendmail(email_origen, email_destino, mensaje.as_string())
        servidor.quit()
    except Exception as e:
        print(f"Error al enviar email: {e}")

def obtener_pais(ip):
    try:
        respuesta = requests.get(f"https://ipapi.co/{ip}/json/")
        datos = respuesta.json()
        return datos.get("country_name", "Desconocido"), datos.get("city", "Desconocida")
    except:
        return "Error", "Error"

# ── SCANNER DE HEADERS ──
def escanner_header(url):
    headers_importantes = {
        "Content-Security-Policy": {
            "descripcion": "Controla recursos de la página",
            "severidad": "Critical",
            "recomendacion": "Agrega en tu servidor: add_header Content-Security-Policy \"default-src 'self'\";"
        },
        "Strict-Transport-Security": {
            "descripcion": "Fuerza conexiones HTTPS",
            "severidad": "High",
            "recomendacion": "Agrega en tu servidor: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\";"
        },
        "X-Content-Type-Options": {
            "descripcion": "Evita adivinanza de archivos",
            "severidad": "Medium",
            "recomendacion": "Agrega en tu servidor: add_header X-Content-Type-Options \"nosniff\";"
        },
        "X-XSS-Protection": {
            "descripcion": "Protege contra ataques XSS",
            "severidad": "Medium",
            "recomendacion": "Agrega en tu servidor: add_header X-XSS-Protection \"1; mode=block\";"
        },
        "Referrer-Policy": {
            "descripcion": "Controla info al navegar",
            "severidad": "Low",
            "recomendacion": "Agrega en tu servidor: add_header Referrer-Policy \"strict-origin-when-cross-origin\";"
        },
        "Permissions-Policy": {
            "descripcion": "Controla APIs del navegador",
            "severidad": "Low",
            "recomendacion": "Agrega en tu servidor: add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\";"
        }
    }

    headers_resultado = {}
    try:
        respuesta = requests.get(url, timeout=5)
        headers_sitio = respuesta.headers
        for header, datos in headers_importantes.items():
            if header in headers_sitio:
                headers_resultado[header] = {
                    "estado": "seguro",
                    "descripcion": datos["descripcion"],
                    "severidad": datos["severidad"],
                    "recomendacion": None
                }
            else:
                headers_resultado[header] = {
                    "estado": "vulnerable",
                    "descripcion": datos["descripcion"],
                    "severidad": datos["severidad"],
                    "recomendacion": datos["recomendacion"]
                }
    except requests.RequestException as e:
        headers_resultado["error"] = str(e)

    return headers_resultado

# ══════════════════════════════════
#           RUTAS
# ══════════════════════════════════

# ── LOGIN ──
@app.route("/")
def inicio():
    if current_user.is_authenticated:
        return redirect(url_for("scanner"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("scanner"))
    
    if request.method == "POST":
        email = sanitizar(request.form.get("email", "").strip().lower())
        password = request.form.get("password", "")
        
        usuarios = cargar_usuarios()
        
        if email in usuarios:
            hash_guardado = usuarios[email]["password"]
            if bcrypt.check_password_hash(hash_guardado, password):
                usuario = Usuario(email, usuarios[email])
                login_user(usuario)
                session.permanent = True
                return redirect(url_for("scanner"))
        
        # Login fallido
        ip = request.remote_addr
        hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        enviar_email(
            "Intento de login fallido",
            f"IP: {ip}\nEmail: {email}\nHora: {hora}"
        )
        flash("Email o contraseña incorrectos", "error")
    
    return render_template("login.html")

# ── REGISTER ──
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("scanner"))
    
    if request.method == "POST":
        nombre = sanitizar(request.form.get("nombre", "").strip())
        email = sanitizar(request.form.get("email", "").strip().lower())
        password = request.form.get("password", "")
        
        # Validaciones
        if not validar_email(email):
            flash("Email inválido", "error")
            return render_template("register.html")
        
        valido, mensaje = validar_password(password)
        if not valido:
            flash(mensaje, "error")
            return render_template("register.html")
        
        usuarios = cargar_usuarios()
        
        if email in usuarios:
            flash("Este email ya está registrado", "error")
            return render_template("register.html")
        
        # Guardar usuario
        hash_password = bcrypt.generate_password_hash(password).decode("utf-8")
        usuarios[email] = {
            "nombre": nombre,
            "password": hash_password,
            "admin": False,
            "fecha_registro": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        guardar_usuarios(usuarios)
        
        enviar_email(
            " Nuevo usuario registrado",
            f"Nombre: {nombre}\nEmail: {email}\nHora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        flash("Cuenta creada exitosamente. Inicia sesión.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")

# ── LOGOUT ──
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ── SCANNER ──
@app.route("/scanner")
@login_required
def scanner():
    return render_template("index.html")

@app.route("/analizar", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def analizar():
    url = sanitizar(request.form.get("url", "").strip())
    
    # Validar que sea una URL real
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    try:
        respuesta = requests.get(url, timeout=5)
        codigo_estado = respuesta.status_code
        resultado = f"Conexion exitosa — codigo de estado: {codigo_estado}"
    except:
        resultado = "No se puede conectar a la URL"
        codigo_estado = "Error"
    
    headers_resultado = escanner_header(url)
    ip_usuario = request.remote_addr
    hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open("logs.txt", "a") as archivo:
        archivo.write(f"URL: {url} | Codigo: {codigo_estado} | IP: {ip_usuario} | Usuario: {current_user.email} | Hora: {hora}\n")
    
    enviar_email(
        "🔍 Nuevo escaneo realizado",
        f"Usuario: {current_user.email}\nURL: {url}\nCodigo: {codigo_estado}\nIP: {ip_usuario}\nHora: {hora}"
    )
    
    return render_template("index.html", resultado=resultado, headers_resultado=headers_resultado)

# ── ADMIN ──
@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if not current_user.es_admin:
        return "<h1 style='color:red'>Acceso denegado</h1>", 403
    
    usuarios = cargar_usuarios()
    
    try:
        with open("logs.txt", "r") as archivo:
            logs = archivo.readlines()
    except:
        logs = ["No hay registros disponibles"]
    
    ip = request.remote_addr
    hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    enviar_email(
        "🔴 Acceso al panel admin",
        f"IP: {ip}\nHora: {hora}"
    )
    
    return render_template("admin.html", logs=logs, usuarios=usuarios)

@app.route("/admin/eliminar/<email>")
@login_required
def eliminar_usuario(email):
    if not current_user.es_admin:
        return "Acceso denegado", 403
    
    usuarios = cargar_usuarios()
    if email in usuarios and not usuarios[email].get("admin"):
        del usuarios[email]
        guardar_usuarios(usuarios)
    
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")