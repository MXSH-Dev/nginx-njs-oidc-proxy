import hmac
import string
import hashlib
import base64
import json

secret = 'PYPd1Hv4J6'
# message = '1515928475.417'
key = secret.encode('utf-8')

# message = json.dumps({"hello":"world"})

# message = "hello=world&hi"

# print(message)
# hmac_result = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
# print(base64.b64encode(hmac_result.digest()))

# signature = base64.urlsafe_b64encode(hmac_result.digest())
# print(signature)
# print( type(signature))
# print(signature.decode('utf-8'))

message = "UserVerifySuccess"
print(message)
hmac_result = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
signature = base64.urlsafe_b64encode(hmac_result.digest())
print(signature)
print( type(signature))
print(signature.decode('utf-8'))

message_bytes = message.encode("utf-8")
encoded_message_bytes = base64.urlsafe_b64encode(message_bytes)
print(encoded_message_bytes.decode('utf-8'))

token=signature.decode('utf-8')+"."+encoded_message_bytes.decode('utf-8')
# token=signature.decode('utf-8')+"."+message
print(token)