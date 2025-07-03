import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Crear app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Configuración CORS para permitir cookies (credentials) desde el frontend (ajusta origen)
CORS(app, supports_credentials=True, origins=["http://localhost:3000", "https://tu-proyecto.vercel.app"])

# Configuración app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mi_clave_secreta')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite3')  # fallback a SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar DB
db = SQLAlchemy(app)

# ──────────────── MODELOS ────────────────
class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Producto(db.Model):
    __tablename__ = 'producto'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    precio = db.Column(db.Float, nullable=False)
    imagen = db.Column(db.String(255))

# ──────────────── AUTENTICACIÓN ────────────────
def verificar_token_cookie():
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        datos = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user = Usuario.query.get(datos['user_id'])
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = verificar_token_cookie()
        if not user:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token inválido o expirado'}), 401
            return redirect(url_for('login_page'))
        return f(user, *args, **kwargs)
    return decorated

# ──────────────── RUTAS API ────────────────

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Se requieren usuario y contraseña'}), 400

    user = Usuario.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Usuario o contraseña incorrectos'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    response = jsonify({'message': 'Login exitoso'})
    response.set_cookie(
        'token',
        token,
        httponly=True,
        max_age=86400,
        samesite='Lax',    # Cambia a 'None' si usas frontend en dominio distinto y usa HTTPS
        secure=False       # Cambia a True en producción con HTTPS
    )
    return response

@app.route('/api/logout', methods=['POST'])
def logout():
    response = jsonify({'message': 'Sesión cerrada'})
    response.set_cookie('token', '', expires=0)
    return response

@app.route('/api/validate-token')
@token_required
def validate_token(current_user):
    return jsonify({'message': f'Token válido para usuario {current_user.username}'})

@app.route('/api/productos', methods=['GET'])
def get_productos():
    productos = Producto.query.all()
    return jsonify([{
        'id': p.id,
        'nombre': p.nombre,
        'descripcion': p.descripcion,
        'precio': p.precio,
        'imagen': p.imagen
    } for p in productos])

@app.route('/api/productos', methods=['POST'])
@token_required
def add_producto(current_user):
    data = request.get_json()
    if not data.get('nombre') or data.get('precio') is None:
        return jsonify({'message': 'Nombre y precio son obligatorios'}), 400

    nuevo = Producto(
        nombre=data['nombre'],
        descripcion=data.get('descripcion'),
        precio=data['precio'],
        imagen=data.get('imagen')
    )
    db.session.add(nuevo)
    db.session.commit()
    return jsonify({'message': 'Producto agregado correctamente'})

@app.route('/api/productos/<int:id>', methods=['PUT'])
@token_required
def update_producto(current_user, id):
    producto = Producto.query.get(id)
    if not producto:
        return jsonify({'message': 'Producto no encontrado'}), 404

    data = request.get_json()
    producto.nombre = data.get('nombre', producto.nombre)
    producto.descripcion = data.get('descripcion', producto.descripcion)
    producto.precio = data.get('precio', producto.precio)
    producto.imagen = data.get('imagen', producto.imagen)
    db.session.commit()

    return jsonify({'message': 'Producto actualizado correctamente'})

@app.route('/api/productos/<int:id>', methods=['DELETE'])
@token_required
def delete_producto(current_user, id):
    producto = Producto.query.get(id)
    if not producto:
        return jsonify({'message': 'Producto no encontrado'}), 404

    db.session.delete(producto)
    db.session.commit()
    return jsonify({'message': 'Producto eliminado correctamente'})

# ──────────────── RUTAS HTML ────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')  # Servir el archivo index.html desde la carpeta principal

@app.route('/login')
def login_page():
    return send_from_directory('.', 'login.html')  # Servir el archivo login.html desde la carpeta principal

@app.route('/admin')
@token_required
def admin_page(current_user):
    return send_from_directory('.', 'admin.html')  # Servir el archivo admin.html desde la carpeta principal

# ──────────────── CONFIG GLOBAL PARA NO CACHEAR RESPUESTAS PROTEGIDAS ────────────────
@app.after_request
def no_cache(response):
    if request.path.startswith('/api/') or request.path == '/admin':
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# ──────────────── INICIO ────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not Usuario.query.filter_by(username='admin').first():
            admin = Usuario(username='admin')
            admin.set_password('1234')  # Cambia esta contraseña en producción
            db.session.add(admin)
            db.session.commit()
            print("Usuario admin creado.")
    app.run(debug=True)