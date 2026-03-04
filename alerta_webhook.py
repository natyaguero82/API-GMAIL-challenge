# ---------------- IMPORTACIÓN DE LIBRERÍAS ----------------
import os                    # Para manejar archivos y rutas locales (como token.json)
import base64                 # Para decodificar el contenido de los correos en base64
import json                   # Para trabajar con JSON (como respuestas de Ngrok API)
import urllib.request         # Para hacer peticiones HTTP simples (leer la API de Ngrok)
import time                   # Para pausar el loop y hacer intervalos
from datetime import datetime # Para registrar la hora de cada alerta
import threading              # Para correr Flask en un hilo paralelo
import requests               # Para enviar POST a la URL del webhook

# Flask y Google API
from flask import Flask, request                       # Servidor web para recibir webhooks
from google.oauth2.credentials import Credentials     # Manejo de credenciales OAuth 2.0
from google_auth_oauthlib.flow import InstalledAppFlow # Flujo de autenticación
from google.auth.transport.requests import Request     # Para refrescar credenciales
from googleapiclient.discovery import build           # Para conectarse a la API de Gmail

# ---------------- CONFIGURACIÓN ----------------
PALABRAS_CLAVE = ["confidencial", "contraseña", "secreto", "privado", "alerta"]
# Lista de palabras que queremos detectar en asunto o cuerpo del correo

EXT_SOSPECHOSOS = [".exe", ".zip", ".js", ".bat", ".scr"]
# Extensiones de adjuntos que consideramos peligrosos o sospechosos

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
# Permiso de solo lectura sobre Gmail (no modificamos correos)

CHECK_INTERVAL = 60
# Intervalo en segundos para revisar nuevos correos

# --------- FLASK PARA RECIBIR WEBHOOK ---------
app = Flask(__name__)  # Inicializamos Flask

@app.route("/alerta", methods=["POST"])
def alerta_webhook():
    """
    Endpoint para recibir alertas por POST.
    Imprime el JSON recibido en consola.
    """
    data = request.json
    print("🔔 Alerta recibida en webhook:")
    print(data)
    return "OK", 200

def run_flask():
    """
    Función para levantar el servidor Flask en el puerto 5000.
    Se ejecuta en un hilo paralelo para no bloquear el script principal.
    """
    app.run(port=5000)

# --------- FUNCIONES NGROK ---------
def get_ngrok_url():
    """
    Consulta la API local de Ngrok para obtener la URL pública automáticamente.
    Retorna la URL HTTPS con /alerta al final.
    """
    try:
        with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels") as response:
            data = json.load(response)
            for tunnel in data["tunnels"]:
                if tunnel["proto"] == "https":
                    # Retorna la URL pública del túnel HTTPS + ruta /alerta
                    return tunnel["public_url"] + "/alerta"
    except Exception as e:
        print(f"❌ No se pudo obtener URL de Ngrok: {e}")
    return None

# --------- AUTENTICACIÓN GMAIL ---------
def authenticate_gmail():
    """
    Maneja la autenticación con Gmail usando OAuth 2.0.
    Guarda o lee token.json para evitar autenticación repetida.
    Devuelve un objeto 'service' para usar la API de Gmail.
    """
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Si las credenciales expiraron, las refrescamos automáticamente
            creds.refresh(Request())
        else:
            # Si no hay credenciales válidas, iniciamos flujo de autenticación
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        # Guardamos token para próximas ejecuciones
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # Creamos el servicio de Gmail
    return build('gmail', 'v1', credentials=creds)

# --------- DETECCIÓN DE ALERTAS ---------
def generar_alerta(subject, sender, attachments, webhook_url):
    """
    Analiza el correo para ver si contiene palabras clave o adjuntos sospechosos.
    Si encuentra algo, genera alerta en consola y la envía al webhook.
    """
    subject_lower = subject.lower()
    # Detectar palabras clave en el asunto
    detected_words = [w for w in PALABRAS_CLAVE if w.lower() in subject_lower]

    # Detectar adjuntos sospechosos según la extensión
    suspicious_attachments = [a for a in attachments if any(a.lower().endswith(ext) for ext in EXT_SOSPECHOSOS)]

    if detected_words or suspicious_attachments:
        # Generar timestamp de la alerta
        event_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        alert_data = {
            "event_time": event_time,
            "subject": subject,
            "sender": sender,
            "detected_words": detected_words,
            "suspicious_attachments": suspicious_attachments
        }

        # Mostrar alerta en consola
        print("\n================ ALERTA DE CORREO =================")
        print(f"🕒 {event_time}")
        print(f"📧 Remitente: {sender}")
        print(f"📝 Asunto: {subject}")
        print(f"⚠️ Palabras detectadas: {detected_words}")
        print(f"📎 Adjuntos sospechosos: {suspicious_attachments}")
        print("==================================================\n")

        # Enviar alerta al webhook si la URL está disponible
        try:
            if webhook_url:
                requests.post(webhook_url, json=alert_data)
        except Exception as e:
            print(f"❌ Error enviando al webhook: {e}")

# --------- REVISIÓN DE EMAILS ---------
def check_emails(service, last_checked_ids, webhook_url, max_emails=20):
    """
    Revisa los últimos correos de Gmail.
    Evita procesar correos ya revisados (last_checked_ids).
    Genera alertas según palabras clave y adjuntos sospechosos.
    """
    try:
        results = service.users().messages().list(userId='me', maxResults=max_emails).execute()
        messages = results.get('messages', [])

        for msg in messages:
            msg_id = msg['id']
            if msg_id in last_checked_ids:
                continue  # ya procesado, lo ignoramos

            # Obtenemos el contenido completo del mensaje
            m = service.users().messages().get(userId='me', id=msg_id).execute()
            payload = m.get('payload', {})
            headers = payload.get('headers', [])

            # Extraemos asunto y remitente
            subject = next((h['value'] for h in headers if h['name']=='Subject'), '')
            sender = next((h['value'] for h in headers if h['name']=='From'), '')

            # Extraemos el cuerpo del mensaje (texto plano)
            body = ''
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                        body_bytes = base64.urlsafe_b64decode(part['body']['data'].encode('ASCII'))
                        body += body_bytes.decode('utf-8') + " "
            elif 'body' in payload and 'data' in payload['body']:
                body_bytes = base64.urlsafe_b64decode(payload['body']['data'].encode('ASCII'))
                body += body_bytes.decode('utf-8')

            # Revisamos adjuntos
            attachments = []
            if 'parts' in payload:
                for part in payload['parts']:
                    if part.get('filename'):
                        attachments.append(part['filename'])

            # Generamos alerta si corresponde
            generar_alerta(subject + " " + body, sender, attachments, webhook_url)
            last_checked_ids.add(msg_id)

    except Exception as e:
        print(f"❌ Error revisando correos: {e}")

# --------- LOOP PRINCIPAL ---------
if __name__ == "__main__":
    # Levantamos Flask en un hilo paralelo para recibir webhooks
    threading.Thread(target=run_flask, daemon=True).start()

    # Detectamos URL pública de Ngrok automáticamente
    print("🔹 Obteniendo URL pública de Ngrok...")
    webhook_url = get_ngrok_url()
    if webhook_url:
        print(f"✅ Webhook público detectado: {webhook_url}")
    else:
        print("⚠️ No se detectó URL de Ngrok. Verifica que Ngrok esté corriendo.")

    # Autenticación Gmail
    service = authenticate_gmail()
    last_checked_ids = set()  # Para evitar duplicar alertas

    print("🔹 Sistema de alertas SOC iniciado. Presiona CTRL+C para detener.")

    # Loop infinito para revisar correos cada CHECK_INTERVAL segundos
    while True:
        try:
            check_emails(service, last_checked_ids, webhook_url)
            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            print("\n⏹️ Sistema detenido por usuario.")
            break
        except Exception as e:
            print(f"❌ Error en loop principal: {e}")
            time.sleep(10)