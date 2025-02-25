import requests
import jwt
import datetime

# Variables de configuración
secret_key = 'tu_clave_secreta'  # La clave secreta que usas en PHP
server_name = 'wit.la'  # El nombre del servidor, igual que en PHP

# Nivel de autorización
LVLADMIN = 10
LVLAUDIT = 5
LVLUSER = 1

# Función para verificar el token JWT
def verify_token(cookie):
    if not cookie:
        print({'error': 'Request incorrecto'})
        return {'error': 'Request incorrecto'}

    try:
        # Extraer el token JWT de la cookie (después de 'Bearer ')
        jwt_token = cookie[4:]  # Se asume que el token comienza en el índice 4

        # Decodificar el token usando la clave secreta
        decoded_token = jwt.decode(jwt_token, secret_key, algorithms=["HS256"])

        # Verificar la validez del token
        now = datetime.datetime.utcnow()
        token_expiration = datetime.datetime.utcfromtimestamp(decoded_token['exp'])
        token_issued_at = datetime.datetime.utcfromtimestamp(decoded_token['nbf'])

        if decoded_token['iss'] != server_name:
            print({'error': 'Token invalido'})
            return {'error': 'Token invalido'}

        if token_issued_at > now or token_expiration < now:
            print({'error': 'Token invalido'})
            return {'error': 'Token invalido'}

        # Si el token es válido, puedes continuar con la lógica
        print({'msg': 'Token válido', 'data': decoded_token})
        return {'msg': 'Token válido', 'data': decoded_token}

    except jwt.ExpiredSignatureError:
        print({'error': 'Token expirado'})
        return {'error': 'Token expirado'}
    except jwt.InvalidTokenError:
        print({'error': 'Token inválido'})
        return {'error': 'Token inválido'}

# Hacer una solicitud HTTPS con el token JWT
def make_request_with_token(url, cookie):
    # Verificar el token antes de realizar la solicitud
    token_response = verify_token(cookie)
    if 'error' in token_response:
        return token_response  # Si hay error en el token, lo retorna

    headers = {
        'Authorization': f'Bearer {cookie[4:]}'  # Añadir el token a los headers
    }

    # Realizar la solicitud HTTPS al servidor remoto
    try:
        response = requests.get(url, headers=headers, verify=True)  # Verificar = True asegura que se valida el certificado SSL
        if response.status_code == 200:
            return response.json()  # Retorna la respuesta en formato JSON
        else:
            return {'error': 'Error en la solicitud', 'status_code': response.status_code}
    except requests.exceptions.RequestException as e:
        return {'error': f'Error de solicitud: {str(e)}'}

# Ejemplo de uso
cookie = "Bearer tu_token_aqui"  # Reemplaza con el valor real de la cookie
url = 'https://example.com/api'  # Reemplaza con la URL a la que deseas hacer la solicitud
result = make_request_with_token(url, cookie)
print(result)
