# API Gmail Challenge

## Descripción

Este proyecto consiste en un sistema simple de detección de contenido
sensible en correos electrónicos utilizando la API de Gmail y Python.

La aplicación se autentica mediante OAuth 2.0, lee los últimos correos
del inbox y analiza el asunto y el cuerpo buscando palabras clave como:

-   confidencial\
-   contraseña\
-   privado

Si encuentra alguna coincidencia, genera una alerta.

La alerta se: - Muestra en consola\
- Guarda en un archivo `alertas.txt`\
- Envía mediante un webhook HTTP (POST) para permitir integración con
otros sistemas

------------------------------------------------------------------------

## Arquitectura

Flujo del sistema:

Gmail API → Script en Python → alertas.txt\
↓\
Webhook (HTTP POST)

El sistema funciona de forma orientada a eventos: cuando se detecta una
palabra sensible, se ejecuta una acción automática.

------------------------------------------------------------------------

## Autenticación

La conexión con Gmail se realiza mediante OAuth 2.0.

Los archivos `credentials.json` y `token.json` no se incluyen en el
repositorio por motivos de seguridad. Deben generarse desde Google Cloud
Console.

------------------------------------------------------------------------

## Tecnologías utilizadas

-   Python 3.11+
-   Gmail API
-   OAuth 2.0
-   Flask
-   Requests
-   Git

------------------------------------------------------------------------

## Ejecución del proyecto

1.  Crear entorno virtual:

    python -m venv venv venv`\Scripts`{=tex}`\activate`{=tex}

2.  Instalar dependencias:

    pip install -r requirements.txt

3.  Ejecutar el webhook:

    python alerta_webhook.py

4.  Ejecutar el detector:

    python main.py

------------------------------------------------------------------------

## Estructura del proyecto

-   main.py: lectura y análisis de correos\
-   alerta_webhook.py: servidor webhook\
-   alertas.txt: almacenamiento local de alertas\
-   requirements.txt: dependencias\
-   setup_env.bat: script de configuración\
-   setup_env_smart.bat: script automático

------------------------------------------------------------------------

## Limitaciones

-   La detección se basa únicamente en palabras clave.\
-   Puede generar falsos positivos.\
-   No realiza análisis contextual avanzado.\
-   El webhook funciona en entorno local.

------------------------------------------------------------------------

## Posibles mejoras

-   Implementar sistema de puntuación de riesgo\
-   Agregar análisis contextual\
-   Incorporar autenticación al webhook\
-   Registrar logs estructurados\
-   Integración con un SIEM\
-   Despliegue en la nube
