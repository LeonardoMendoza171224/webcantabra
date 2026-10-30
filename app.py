"""
WEB-Cántabra - Sistema de procesamiento de órdenes de compra
SPRINT 1: Login por roles + Catálogo de productos (versión con seguridad reforzada)

Medidas de seguridad incluidas:
  - Consultas SQL parametrizadas (contra inyección SQL)
  - Escape automático de HTML en las plantillas (contra XSS)
  - Token CSRF en todos los formularios POST
  - Contraseñas cifradas (hash con sal) y mensaje de error genérico en el login
  - Bloqueo temporal tras varios intentos fallidos (contra fuerza bruta)
  - Cookies de sesión HttpOnly + SameSite, y sesión que expira por inactividad
  - Cabeceras de seguridad (CSP, X-Frame-Options, etc.)
  - Control de acceso por rol en el servidor
  - Validación de datos de entrada (tipos, rangos y longitudes)
  - Páginas de error propias, sin mostrar detalles internos
  - Registro de eventos de seguridad en seguridad.log
"""
import hmac
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g, abort)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("WEBCANTABRA_DB", os.path.join(BASE_DIR, "webcantabra.db"))


def cargar_clave_secreta():
    """La clave secreta NO va escrita en el código: se toma del entorno o se genera sola."""
    desde_entorno = os.environ.get("SECRET_KEY")
    if desde_entorno:
        return desde_entorno
    ruta = os.path.join(BASE_DIR, "secret.key")
    if not os.path.exists(ruta):
        with open(ruta, "w") as f:
            f.write(secrets.token_hex(32))
    with open(ruta) as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = cargar_clave_secreta()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,        # el JavaScript no puede leer la cookie
    SESSION_COOKIE_SAMESITE="Lax",       # la cookie no viaja en peticiones de otros sitios
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",  # activar al publicar con HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),      # expira por inactividad
    MAX_CONTENT_LENGTH=1024 * 1024,      # máximo 1 MB por petición
    TEMPLATES_AUTO_RELOAD=True,
)

# Registro de eventos de seguridad
log_seguridad = logging.getLogger("seguridad")
log_seguridad.setLevel(logging.INFO)
if not log_seguridad.handlers:
    _h = logging.FileHandler(os.path.join(BASE_DIR, "seguridad.log"), encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    log_seguridad.addHandler(_h)


# ---------------------------------------------------------------
# BASE DE DATOS
# ---------------------------------------------------------------
def get_db():
    """Abre la conexión a la base de datos (una por petición)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Crea las tablas y carga datos ficticios si la base está vacía."""
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            nombre  TEXT NOT NULL,
            clave   TEXT NOT NULL,
            rol     TEXT NOT NULL CHECK (rol IN ('cliente','vendedor','almacen'))
        );
        CREATE TABLE IF NOT EXISTS productos (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo    TEXT UNIQUE NOT NULL,
            nombre    TEXT NOT NULL,
            categoria TEXT NOT NULL,
            proveedor TEXT NOT NULL,
            precio    REAL NOT NULL CHECK (precio >= 0),
            stock     INTEGER NOT NULL CHECK (stock >= 0)
        );
    """)

    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        usuarios = [
            ("cliente1",  "Carlos Mendoza", "cliente"),
            ("vendedor1", "Lucía Paredes",  "vendedor"),
            ("almacen1",  "Jorge Salinas",  "almacen"),
        ]
        for usuario, nombre, rol in usuarios:
            db.execute(
                "INSERT INTO usuarios (usuario, nombre, clave, rol) VALUES (?,?,?,?)",
                (usuario, nombre, generate_password_hash("1234"), rol))

    if db.execute("SELECT COUNT(*) FROM productos").fetchone()[0] == 0:
        productos = [
            ("TEC-001", "Auriculares Bluetooth",   "Tecnología", "TecnoSur S.A.",   89.90, 40),
            ("TEC-002", "Teclado mecánico",        "Tecnología", "TecnoSur S.A.",  159.00, 25),
            ("TEC-003", "Mouse inalámbrico",       "Tecnología", "TecnoSur S.A.",   45.50, 60),
            ("TEC-004", "Monitor 24 pulgadas",     "Tecnología", "VisionTech",     599.00, 12),
            ("OFI-001", "Silla ergonómica",        "Oficina",    "OficinaPlus",    389.00,  8),
            ("OFI-002", "Escritorio de madera",    "Oficina",    "OficinaPlus",    450.00,  6),
            ("OFI-003", "Lámpara LED de escritorio","Oficina",   "OficinaPlus",     65.00, 30),
            ("HOG-001", "Mochila impermeable",     "Hogar",      "HogarNorte",     120.00, 35),
            ("HOG-002", "Termo de acero 1L",       "Hogar",      "HogarNorte",      55.00,  4),
            ("HOG-003", "Set de organizadores",    "Hogar",      "HogarNorte",      38.00, 50),
        ]
        db.executemany(
            "INSERT INTO productos (codigo, nombre, categoria, proveedor, precio, stock) "
            "VALUES (?,?,?,?,?,?)", productos)

    db.commit()
    db.close()


# ---------------------------------------------------------------
# SEGURIDAD GENERAL: CSRF, cabeceras y errores
# ---------------------------------------------------------------
def generar_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.context_processor
def inyectar_csrf():
    return {"csrf_token": generar_csrf}


@app.before_request
def verificar_csrf():
    """Toda petición POST debe traer el token secreto de la sesión."""
    if request.method == "POST":
        esperado = session.get("csrf", "")
        recibido = request.form.get("csrf_token", "")
        if not esperado or not hmac.compare_digest(esperado, recibido):
            log_seguridad.warning("CSRF rechazado | ip=%s | ruta=%s", request.remote_addr, request.path)
            abort(400)


@app.after_request
def cabeceras_seguridad(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
    resp.headers["Cache-Control"] = "no-store"   # no guardar páginas privadas en caché
    return resp


MENSAJES_ERROR = {
    400: "Solicitud no válida o sesión expirada. Vuelve a cargar la página e inténtalo de nuevo.",
    404: "La página que buscas no existe.",
    405: "Acción no permitida.",
    413: "El envío es demasiado grande.",
    500: "Ocurrió un error interno. Inténtalo más tarde.",
}


def pagina_error(error):
    codigo = getattr(error, "code", 500)
    if codigo == 500:
        app.logger.exception("Error interno")
    return render_template("error.html", codigo=codigo,
                           mensaje=MENSAJES_ERROR.get(codigo, "Ocurrió un error.")), codigo


for _codigo in (400, 404, 405, 413, 500):
    app.register_error_handler(_codigo, pagina_error)


# ---------------------------------------------------------------
# CONTROL DE ACCESO (login y roles)
# ---------------------------------------------------------------
def login_requerido(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if "usuario_id" not in session:
            flash("Debes iniciar sesión primero.", "warning")
            return redirect(url_for("login"))
        return vista(*args, **kwargs)
    return envoltura


def rol_requerido(*roles):
    def decorador(vista):
        @wraps(vista)
        @login_requerido
        def envoltura(*args, **kwargs):
            if session.get("rol") not in roles:
                log_seguridad.warning("Acceso denegado | usuario_id=%s | rol=%s | ruta=%s",
                                      session.get("usuario_id"), session.get("rol"), request.path)
                flash("No tienes permiso para entrar a esa sección.", "danger")
                return redirect(url_for("catalogo"))
            return vista(*args, **kwargs)
        return envoltura
    return decorador


# ---------------------------------------------------------------
# RUTAS
# ---------------------------------------------------------------
@app.route("/")
def inicio():
    if "usuario_id" in session:
        return redirect(url_for("catalogo"))
    return redirect(url_for("login"))


# Protección contra fuerza bruta: máximo 5 fallos y bloqueo de 5 minutos
MAX_INTENTOS = 5
BLOQUEO_SEGUNDOS = 300
INTENTOS_FALLIDOS = {}   # clave -> {"n": fallos, "hasta": momento de desbloqueo}
CLAVE_FALSA = generate_password_hash("clave-falsa")  # evita diferencias de tiempo si el usuario no existe


def esta_bloqueado(clave):
    dato = INTENTOS_FALLIDOS.get(clave)
    return bool(dato and dato["hasta"] > time.time())


def registrar_fallo(clave):
    dato = INTENTOS_FALLIDOS.setdefault(clave, {"n": 0, "hasta": 0})
    if dato["hasta"] and dato["hasta"] <= time.time():   # el bloqueo anterior ya venció
        dato["n"], dato["hasta"] = 0, 0
    dato["n"] += 1
    if dato["n"] >= MAX_INTENTOS:
        dato["hasta"] = time.time() + BLOQUEO_SEGUNDOS


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()[:50]
        clave = request.form.get("clave", "")[:128]
        ip = request.remote_addr or "?"
        claves_limite = (f"ip:{ip}", f"user:{usuario.lower()}")

        if any(esta_bloqueado(k) for k in claves_limite):
            log_seguridad.warning("Login bloqueado | usuario=%s | ip=%s", usuario, ip)
            flash("Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo.", "danger")
            return render_template("login.html"), 429

        fila = get_db().execute(
            "SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
        valido = check_password_hash(fila["clave"] if fila else CLAVE_FALSA, clave)

        if fila and valido:
            for k in claves_limite:
                INTENTOS_FALLIDOS.pop(k, None)
            session.clear()                      # evita fijación de sesión
            session.permanent = True
            session["usuario_id"] = fila["id"]
            session["nombre"] = fila["nombre"]
            session["rol"] = fila["rol"]
            log_seguridad.info("Login correcto | usuario=%s | ip=%s", usuario, ip)
            flash(f"Bienvenido, {fila['nombre']}.", "success")
            return redirect(url_for("catalogo"))

        for k in claves_limite:
            registrar_fallo(k)
        log_seguridad.warning("Login fallido | usuario=%s | ip=%s", usuario, ip)
        flash("Usuario o contraseña incorrectos.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))


@app.route("/catalogo")
@login_requerido
def catalogo():
    busqueda = request.args.get("q", "").strip()
    categoria = request.args.get("categoria", "").strip()

    sql = "SELECT * FROM productos WHERE 1=1"
    params = []
    if busqueda:
        sql += " AND (nombre LIKE ? OR codigo LIKE ?)"
        params += [f"%{busqueda}%", f"%{busqueda}%"]
    if categoria:
        sql += " AND categoria = ?"
        params.append(categoria)
    sql += " ORDER BY categoria, nombre"

    db = get_db()
    productos = db.execute(sql, params).fetchall()
    categorias = [f["categoria"] for f in db.execute(
        "SELECT DISTINCT categoria FROM productos ORDER BY categoria")]
    return render_template("catalogo.html", productos=productos,
                           categorias=categorias, busqueda=busqueda,
                           categoria_sel=categoria)


def leer_formulario_producto():
    """Lee y valida los datos del formulario de producto."""
    datos = {
        "codigo": request.form.get("codigo", "").strip().upper(),
        "nombre": request.form.get("nombre", "").strip(),
        "categoria": request.form.get("categoria", "").strip(),
        "proveedor": request.form.get("proveedor", "").strip(),
        "precio": request.form.get("precio", "").strip(),
        "stock": request.form.get("stock", "").strip(),
    }
    if not all(datos.values()):
        return datos, "Completa todos los campos."
    if not re.fullmatch(r"[A-Z0-9\-]{1,20}", datos["codigo"]):
        return datos, "El código solo puede tener letras, números y guiones (máx. 20)."
    if len(datos["nombre"]) > 100 or len(datos["proveedor"]) > 100 or len(datos["categoria"]) > 50:
        return datos, "Algún texto es demasiado largo."
    try:
        datos["precio"] = round(float(datos["precio"]), 2)
        datos["stock"] = int(datos["stock"])
    except ValueError:
        return datos, "Precio y stock deben ser números válidos."
    if datos["precio"] != datos["precio"] or datos["precio"] in (float("inf"), float("-inf")):
        return datos, "El precio no es válido."
    if datos["precio"] < 0 or datos["stock"] < 0:
        return datos, "Precio y stock no pueden ser negativos."
    if datos["precio"] > 100000 or datos["stock"] > 100000:
        return datos, "Precio o stock fuera del rango permitido."
    return datos, None


@app.route("/producto/nuevo", methods=["GET", "POST"])
@rol_requerido("vendedor")
def producto_nuevo():
    datos = {}
    if request.method == "POST":
        datos, error = leer_formulario_producto()
        if error:
            flash(error, "danger")
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO productos (codigo, nombre, categoria, proveedor, precio, stock) "
                    "VALUES (:codigo, :nombre, :categoria, :proveedor, :precio, :stock)", datos)
                db.commit()
                flash("Producto registrado correctamente.", "success")
                return redirect(url_for("catalogo"))
            except sqlite3.IntegrityError:
                flash("Ya existe un producto con ese código.", "danger")
    return render_template("producto_form.html", datos=datos, editando=False)


@app.route("/producto/<int:producto_id>/editar", methods=["GET", "POST"])
@rol_requerido("vendedor")
def producto_editar(producto_id):
    db = get_db()
    producto = db.execute("SELECT * FROM productos WHERE id = ?", (producto_id,)).fetchone()
    if producto is None:
        flash("El producto no existe.", "danger")
        return redirect(url_for("catalogo"))

    datos = dict(producto)
    if request.method == "POST":
        datos, error = leer_formulario_producto()
        if error:
            flash(error, "danger")
        else:
            try:
                datos["id"] = producto_id
                db.execute(
                    "UPDATE productos SET codigo=:codigo, nombre=:nombre, categoria=:categoria, "
                    "proveedor=:proveedor, precio=:precio, stock=:stock WHERE id=:id", datos)
                db.commit()
                flash("Producto actualizado correctamente.", "success")
                return redirect(url_for("catalogo"))
            except sqlite3.IntegrityError:
                flash("Ya existe un producto con ese código.", "danger")
    return render_template("producto_form.html", datos=datos, editando=True)


# ---------------------------------------------------------------
# INICIO DE LA APLICACIÓN
# ---------------------------------------------------------------
init_db()

if __name__ == "__main__":
    # Sin depurador interactivo (es un riesgo de seguridad); solo escucha en tu propio equipo.
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=True)
