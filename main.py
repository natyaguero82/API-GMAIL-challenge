import os
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from datetime import datetime

# Librerías de Google para autenticación OAuth 2.0
# Conexión por API y servicio de correo
# Gestión de credenciales

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']  # Permisos solo lectura

KEYWORDS = ["confidencial", "contraseña"]
WHITELIST_DOMAINS = ["empresa.com", "google.com"]
SUSPICIOUS_EXTENSIONS = [".zip", ".exe", ".js", ".bat"]

# Función de inicio de sesión en Gmail
def authenticate():
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return creds

# Función para extraer el texto del body decodificando contenido base64
def get_email_body(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body']['data']
                return base64.urlsafe_b64decode(data).decode('utf-8')
    else:
        data = payload['body'].get('data')
        if data:
            return base64.urlsafe_b64decode(data).decode('utf-8')

    return ""

# Función para analizar los últimos correos
def analyze_emails(service):
    results = service.users().messages().list(userId='me', maxResults=10).execute()
    messages = results.get('messages', [])

    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
        headers = msg_data['payload']['headers']

        subject = ""
        sender = ""

        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            if header['name'] == 'From':
                sender = header['value']

        # Whitelist
        sender_domain = sender.split('@')[-1].replace('>', '')
        if any(domain in sender_domain for domain in WHITELIST_DOMAINS):
            continue

        body = get_email_body(msg_data['payload'])
        full_text = (subject + " " + body).lower()

        # Detecta palabras sensibles
        detected_words = [word for word in KEYWORDS if word in full_text]

        # Analiza adjuntos sospechosos
        suspicious_attachments = []
        if 'parts' in msg_data['payload']:
            for part in msg_data['payload']['parts']:
                filename = part.get('filename')
                if filename:
                    for ext in SUSPICIOUS_EXTENSIONS:
                        if filename.endswith(ext):
                            suspicious_attachments.append(filename)

        # Genera alerta si se detectan palabras o adjuntos sospechosos
        if detected_words or suspicious_attachments:
            event_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            alert_message = f"""
Event Time: {event_time}
Asunto: {subject}
Remitente: {sender}
Palabras detectadas: {detected_words}
Adjuntos sospechosos: {suspicious_attachments}
----------------------------------------
"""

            print(alert_message)

            with open("alertas.txt", "a", encoding="utf-8") as f:
                f.write(alert_message)

# Función principal
def main():
    creds = authenticate()
    service = build('gmail', 'v1', credentials=creds)
    analyze_emails(service)

if __name__ == '__main__':
    main()

