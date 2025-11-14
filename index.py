import json
import random
import hashlib
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file
# 🔒 FIX A02: se usa bcrypt para hashing/verificación de contraseñas
import bcrypt
# 🔒 FIX A04: para validar tipo MIME y tamaño de imagen
import imghdr
import secrets
# 🔒 FIX A05
import os

AUDIT_LOG_PATH = os.getenv('AUDIT_LOG_PATH')  
APP_DEBUG = os.getenv('APP_DEBUG', '0') == '1'

def loadDatabaseSettings(pathjs):
	# 🔒 FIX A05: Prefer env vars; fallback to db.json
	env_host = os.getenv('DB_HOST')
	if env_host:
		# Read DB settings from environment
		return {
			'host': env_host,
			'port': int(os.getenv('DB_PORT', '3306')),
			'dbname': os.getenv('DB_NAME', ''),
			'user': os.getenv('DB_USER', ''),
			'password': os.getenv('DB_PASS', '')
		}
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson
	
"""
function loadDatabaseSettings(pathjs):
	string = file_get_contents(pathjs);
	json_a = json_decode(string, true);
	return json_a;

"""
def getToken():
	tiempo = datetime.now().timestamp()
	numero = random.random()
	cadena = str(tiempo) + str(numero)
	numero2 = random.random()
	cadena2 = str(numero)+str(tiempo)+str(numero2)
	m = hashlib.sha1()
	m.update(cadena.encode())
	P = m.hexdigest()
	m = hashlib.md5()
	m.update(cadena.encode())
	Q = m.hexdigest()
	return f"{P[:20]}{Q[20:]}"

"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""
@post('/Registro')
def Registro():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	####/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	#posible vulnerabilidad
	try:
		with db.cursor() as cursor:
			# 🔒 FIX A02: usar bcrypt para hashear la contraseña y consultas parametrizadas
			uname = request.json["uname"]
			email = request.json["email"]
			password = request.json["password"]
			# generar hash seguro con bcrypt
			hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
			# insertar usando parámetros para evitar inyección (además de reemplazar MD5)
			cursor.execute("INSERT INTO Usuario (uname, email, password) VALUES (%s, %s, %s)", (uname, email, hashed))
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		# 🔒 FIX A05: evitar filtrar detalles sensibles en logs; registrar solo la excepción tipo/mesaje genérico
		print("Error en Registro:", str(e))
		return {"R":-2}
	return {"R":0,"D":R}




"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'uname' in request.json  and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			# 🔒 FIX A02: obtener hash desde BD y verificar con bcrypt (no usar md5 en la query)
			uname = request.json["uname"]
			password = request.json["password"]
			# No imprimir contraseñas en logs
			print(f'Select id and password from Usuario where uname = %s', uname)
			cursor.execute("SELECT id, password FROM Usuario WHERE uname = %s", (uname,))
			R = cursor.fetchall()
			# verificar que exista usuario y que la contraseña coincida usando bcrypt
			if not R:
				# usuario no encontrado
				db.close()
				return {"R": -3}
			# R[0][1] es el hash almacenado
			stored_hash = R[0][1]
			# comprobar con bcrypt
			if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
				db.close()
				return {"R": -3}
	except Exception as e: 
		# 🔒 FIX A05: evitar detalles sensibles en la salida; registrar error genérico
		print("Error en Login:", str(e))
		db.close()
		return {"R":-2}
	
	
	# en adelante se usa el id del usuario verificado
	user_id = R[0][0]
	
	T = getToken();
	# 🔒 FIX A05: no escribir tokens en texto plano en /tmp/log. Si AUDIT_LOG_PATH está definido, escribir solo hash del token.
	if AUDIT_LOG_PATH:
		try:
			token_hash = hashlib.sha256(T.encode()).hexdigest()
			audit_path = Path(AUDIT_LOG_PATH)
			# Crear archivo de log si no existe (no crear en rutas públicas); establecer permisos restrictivos si es posible
			audit_path.parent.mkdir(parents=True, exist_ok=True)
			with audit_path.open("a") as logf:
				logf.write(f"user:{user_id} token_hash:{token_hash} time:{datetime.utcnow().isoformat()} event:token_created\n")
			# Si el OS lo permite, restringir permisos (intentar, no fallar si no se permite)
			try:
				audit_path.chmod(0o600)
			except Exception:
				pass
		except Exception as e:
			# Si no se puede escribir el log, no interrumpir el login; solo emitir mensaje mínimo
			print("Warning: audit log unavailable")
	
	
	try:
		with db.cursor() as cursor:
			# 🔒 FIX A02: usar parámetros para las consultas de AccesoToken aquí también (evita concatenación)
			cursor.execute("Delete from AccesoToken where id_Usuario = %s", (user_id,))
			cursor.execute("insert into AccesoToken (id_Usuario, token, fecha) values (%s, %s, now())", (user_id, T))
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 * 
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",
 * 		"ext": "PNG"
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	# Validar si el usuario esta en la base de datos
	TKN = request.json['token'];
	
	R = False
	try:
		with db.cursor() as cursor:
			# 🔒 FIX A03: usar query parametrizada para evitar SQL injection con token
			cursor.execute("SELECT id_Usuario FROM AccesoToken WHERE token = %s", (TKN,))
			R = cursor.fetchall()
	except Exception as e: 
		print("Error validando token:", str(e))
		db.close()
		return {"R":-2}
	
	
	id_Usuario = R[0][0]

	# 🔒 FIX A04: validar extensión segura
	ext = request.json['ext'].lower()
	ext_permitidas = ['jpg', 'jpeg', 'png', 'gif']
	if ext not in ext_permitidas:
		return {"R": -5, "msg": "Extensión no permitida"}
	# 🔒 FIX A04: validar tamaño del archivo (base64)
	try:
		data_b64 = request.json['data']
		data_bytes = base64.b64decode(data_b64, validate=True)
	except Exception:
		return {"R": -6, "msg": "Datos base64 inválidos"}

	if len(data_bytes) > 5 * 1024 * 1024:  # 5 MB
		return {"R": -7, "msg": "Archivo demasiado grande"}

	# 🔒 FIX A04: verificar tipo MIME (solo imágenes)
	tmp_name = secrets.token_hex(8)
	tmp_path = tmp / tmp_name
	try:
		with open(tmp_path, "wb") as imagen:
			imagen.write(data_bytes)
		# Intentar restringir permisos al archivo temporal
		try:
			tmp_path.chmod(0o600)
		except Exception:
			pass
		tipo = imghdr.what(tmp_path)
		if tipo not in ext_permitidas:
			tmp_path.unlink(missing_ok=True)
			return {"R": -8, "msg": "Tipo de archivo no válido"}
	except Exception as e:
		print("Error almacenando temporal:", str(e))
		tmp_path.unlink(missing_ok=True)
		return {"R": -6, "msg": "Error al procesar archivo"}
	
	############################
	############################
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			# 🔒 FIX A03: insertar usando parámetros para evitar SQL injection
			cursor.execute("INSERT INTO Imagen (name, ruta, id_Usuario) VALUES (%s, %s, %s)", (request.json["name"], "img/", id_Usuario))
			# 🔒 FIX A03: seleccionar max(id) usando parámetros
			cursor.execute("SELECT MAX(id) as idImagen FROM Imagen WHERE id_Usuario = %s", (id_Usuario,))
			R = cursor.fetchall()
			idImagen = R[0][0];
			# 🔒 FIX A03: actualizar ruta usando parámetros (evitar concatenación en SQL)
			new_ruta = f"img/{idImagen}.{ext}"
			cursor.execute("UPDATE Imagen SET ruta = %s WHERE id = %s", (new_ruta, idImagen))
			db.commit()
			# 🔒 FIX A04: mover archivo de forma segura
			final_path = img / f"{idImagen}.{ext}"
			shutil.move(str(tmp_path), final_path)
			try:
				final_path.chmod(0o640)
			except Exception:
				pass
			return {"R":0,"D":idImagen}
	except Exception as e: 
		print("Error guardando Imagen:", str(e))
		db.close()
		# limpiar temporal si quedó
		try:
			tmp_path.unlink(missing_ok=True)
		except Exception:
			pass
		return {"R":-3}


"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Descargar')
def Descargar():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	R = False
	try:
		with db.cursor() as cursor:
			# 🔒 FIX A03: usar query parametrizada para evitar SQL injection con token
			cursor.execute("SELECT id_Usuario FROM AccesoToken WHERE token = %s", (TKN,))
			R = cursor.fetchall()
	except Exception as e: 
		print("Error validando token en Descargar:", str(e))
		db.close()
		return {"R":-2}
		
	
	
	# Buscar imagen y enviarla
	# 🔒 FIX A01: verificar que la imagen pertenezca al usuario asociado al token
	try:
		with db.cursor() as cursor:
			id_usuario = R[0][0]
			cursor.execute("SELECT name, ruta FROM Imagen WHERE id = %s AND id_Usuario = %s", (idImagen, id_usuario))
			row = cursor.fetchone()
			if not row:
				db.close()
				return {"R": -9, "msg": "No tienes permiso para acceder a esta imagen"}

			img_root = Path('img').resolve()
			ruta = Path(row[1]).resolve()
			if not str(ruta).startswith(str(img_root)):
				db.close()
				return {"R": -10, "msg": "Ruta de imagen no permitida"}
			db.close()
			return static_file(ruta.name, root=str(img_root))
	except Exception as e: 
		print("Error en Descargar:", str(e))
		db.close()
		return {"R":-3}

if __name__ == '__main__':
     # 🔒 FIX A05: Controlar debug por variable de entorno (no debug=True en prod)
    run(host=os.getenv('HOST', '0.0.0.0'), port=int(os.getenv('PORT', '8080')), debug=APP_DEBUG)
