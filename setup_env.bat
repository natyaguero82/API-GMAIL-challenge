@echo off
REM ---------------------------------------
REM Script completo de configuración y ejecución para Gmail API
REM ---------------------------------------

REM 1️⃣ Crear entorno virtual
python -m venv venv

REM 2️⃣ Activar entorno virtual
call .\venv\Scripts\activate

REM 3️⃣ Actualizar pip
python -m pip install --upgrade pip

REM 4️⃣ Instalar librerías necesarias
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib

REM 5️⃣ Verificar instalación
python -c "from googleapiclient.discovery import build; print('✅ Google API funciona')"

REM 6️⃣ Ejecutar el script principal
echo.
echo -------------------------------
echo Ejecutando main.py...
echo -------------------------------
python main.py

echo.
echo -------------------------------
echo Script terminado.
echo -------------------------------
echo Para usar el entorno en el futuro:
echo call .\venv\Scripts\activate
pause