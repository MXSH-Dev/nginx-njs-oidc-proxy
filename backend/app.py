
import requests
import os
from flask import request, Response, Flask, jsonify
import json
app = Flask(__name__)


@app.route("/")
def health():
    cookies = request.cookies.to_dict()
    return jsonify(status="green", message="success", headers=dict(request.headers), cookies=cookies,values=request.values.to_dict()), 200


@app.route("/google/token",methods=["POST","GET"])
def token():
    app.logger.info("---------------------------")
    cookies = request.cookies.to_dict()
    values= request.values.to_dict()
    headers=dict(request.headers)
    json_values = request.json

    app.logger.info("headers------------")
    app.logger.info(json.dumps(headers,indent=2))
    app.logger.info("values------------")
    app.logger.info(json.dumps(values,indent=2))
    app.logger.info("json------------")
    app.logger.info(json.dumps(json_values,indent=2))

    request_url = "https://oauth2.googleapis.com/token"

    resp = requests.post(url=request_url, data=json_values,
                         timeout=10, verify=False)
    resp_json = resp.json()
    app.logger.info("resp------------")
    app.logger.info(json.dumps(resp_json,indent=2))


    resp2 = requests.post(url=request_url, data=json_values,
                         timeout=10, verify=False)
    resp_json2 = resp2.json()
    app.logger.info("resp2------------")
    app.logger.info(json.dumps(resp_json2,indent=2))
    
    return resp_json,resp.status_code

    # return json.dumps(json_values),200

if __name__ == '__main__':
    PROT = os.getenv("PORT", 9999)
    print(f'This server is running on port: {PROT}')
    app.run(debug=True, host='0.0.0.0', port=PROT)
