import crypto from "crypto";

var sign = data => crypto.createHmac("sha256", "IamSomeCookieSecret").update(data).digest("base64url");

// var sign = data => crypto.createHmac("sha256", "IamSomeCookieSecret").update(data).digest("base64");

// var my_data = sign("hello");

// console.log(my_data)

// var cookie = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE2NDkxOTYwNjQsImV4cCI6MTY0OTgwMDg2NCwidXNlciI6Im1pY2hhZWx4aW5ndGVsdXMiLCJlbWFpbCI6Im1pY2hhZWx4aW5ndGVsdXNAZ21haWwuY29tIn0.BtaAKlG5rlccO5v0crTzutRBK_EFkPLDTZe4_3EeX3E"

var verifySignedCookie = signedCookie => {
	var fragments = signedCookie.split(".");
	if (fragments.length !== 3) {
		throw new Error("invalid cookie format");
	}

	var signature = fragments.pop();

    console.log(signature)

    console.log(fragments.join("."))

    console.log(sign(fragments.join(".")))

	if (signature !== sign(fragments.join("."))) {
		throw new Error("invalid signature");
	}

	// var claims = JSON.parse(String.bytesFrom(fragments.pop(), "base64url"));

    var claims = atob(fragments.pop());

	// var now = Math.floor(new Date().getTime() / 1000);
	// if (now < claims.nbf || claims.exp < now) {
	// 	throw new Error("expired cookie");
	// }

	return claims;
};

// var my_claims = verifySignedCookie(cookie)

// console.log(my_claims)

console.log("**************************** createSignedCookie ************************************")

var createSignedCookie = data => {
	var header = {
		alg: "HS256",
		typ: "JWT",
	};

	// var now = Math.floor(new Date().getTime() / 1000);

	// console.log(now)

	var now = 1649584711
	var claims = Object.assign({
		// nbf: now,
		exp: now,
	}, data);

	// var fragments = [header, claims].map(e => JSON.stringify(e).toUTF8().toString("base64url"));

    var fragments = [header, claims].map(e => btoa(JSON.stringify(e)));

	// console.log(fragments,"---1")
    // var fragments = [header, claims].map(e => JSON.stringify(e).toBytes().toString('base64'));

	fragments.push(sign(fragments.join(".")));

	// console.log(fragments,"---2")

	return fragments.join(".");
};

// var my_new_cookie = createSignedCookie({"hello":"https://world"})

// console.log(my_new_cookie)

// console.log("****************************************************************")

// var my_claims2 = verifySignedCookie(my_new_cookie)

// console.log(my_claims2)


console.log("############## test self encode decode #####################")
var secret = 'PYPd1Hv4J6';
// var message = '1515928475.417'

// var message = JSON.stringify({hello:"world"})

var message = "hello=world&hi"
console.log(message)
var hmac = crypto.createHmac('sha256', secret);
var hmac_result = hmac.update(message).digest('base64');
console.log(hmac_result)


