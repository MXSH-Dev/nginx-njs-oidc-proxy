import crypto from "crypto";

var secret = 'PYPd1Hv4J6';
// var message = '1515928475.417'

// var message = JSON.stringify({hello:"world"})

// var message = "hello=world&hi"
// console.log(message)
// var hmac = crypto.createHmac('sha256', secret);
// var hmac_result = hmac.update(message).digest('base64');
// console.log(hmac_result)

// var ck = "5xbmvPxVi7Dfg3Jz5EXKXixneZEfNdHbWIzGVYWkznE=.UserVerifySuccess"

var ck = "5xbmvPxVi7Dfg3Jz5EXKXixneZEfNdHbWIzGVYWkznE=.VXNlclZlcmlmeVN1Y2Nlc3M="

var fgs = ck.split(".");

var sg = fgs[0]

console.log("signature 1 : ",sg)

var hmac = crypto.createHmac('sha256', secret);

var msg = atob(fgs[1])
var hmac_result = hmac.update(msg).digest('base64');
console.log(hmac_result)