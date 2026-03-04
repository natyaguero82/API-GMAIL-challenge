# webhook_server.py
from flask import Flask, request

app = Flask(__name__)

@app.route("/alerta", methods=["POST"])
def alerta():
    data = request.json  # recibe JSON
    print("🔔 Alerta recibida:")
    print(data)
    return "OK", 200

if __name__ == "__main__":
    app.run(port=5000)  # corre en http://localhost:5000/alerta