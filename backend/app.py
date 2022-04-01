
import requests
import os
from flask import request, Response, Flask, jsonify
app = Flask(__name__)


@app.route("/")
def health():
    return jsonify(status="green", message="success",headers=dict(request.headers)), 200

if __name__ == '__main__':
    PROT = os.getenv("PORT", 9999)
    print(f'This server is running on port: {PROT}')
    app.run(debug=True, host='0.0.0.0', port=PROT)
