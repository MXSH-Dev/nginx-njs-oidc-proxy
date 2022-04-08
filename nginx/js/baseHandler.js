import lib from "js/lib.js";

// `printError` puts error message to user-agent with code=500, and deletes cookie.
var printError = (r, code, msg) => {
	r.headersOut["Content-Type"] = "text/plain";
	lib.cookie.set(r, null);
	r.return(code, msg);
};

// `baseHandler` is higher-order function, which receives `inheritedHandler`(function) and returns new handler which catches errors throwed in `inheritedHandler`.
var baseHandler = inheritedHandler => r => {
	try {
		inheritedHandler(r);
	} catch(e) {
		var reqId = r.variables["request_id"];
		printError(r, 500, `An error occured. Please contact with administrators, and tell them a tracking reference: ${reqId}`);

		r.error(`[baseHandler] Failed: req_id=${reqId}, error=${e}`);
	}
};

// `callbackHandler` is handler, which handles oauth2 callback.
var callbackHandler = baseHandler(r => {
	var context = lib.cookie.get(r);

	// When `expectedState`(read from UA's cookie) and `actualState`(passed from OpenID provider) are not match, this request must be rejected.
	var expectedState = context.state;
	var actualState = decodeURIComponent(r.variables["arg_state"]);
	if (expectedState !== actualState) {
		throw new Error(`unmached state: expected=${expectedState}, actual=${actualState}`);
	}

	// Exchange code with ID token.
	var query = {
		code: decodeURIComponent(r.variables["arg_code"]),
		client_id: lib.oauthClient.getId(),
		client_secret: lib.oauthClient.getSecret(),
		grant_type: "authorization_code",
		// redirect_uri: `${r.variables["scheme"]}://${r.variables["host"]}/oauth2/callback`,
		redirect_uri: `${r.variables["scheme"]}://${r.variables["host"]}:8080/oauth2/callback`,
	};
	r.subrequest("/oauth2/internal/token", {method: "POST", body: JSON.stringify(query)}, sr => {
		if (sr.status !== 200) {
			throw new Error(`failed to fetch token: status=${sr.status}, resp=${sr.responseBody}`);
		}

		// Parse ID token, which is encoded with JWT.
		var resp = JSON.parse(sr.responseBody);
		var fragments = (resp.id_token || "").split(".");
		if (fragments.length !== 3) {
			throw new Error(`invalid id_token format: id_token=${resp.id_token}`);
		}

		var claims = JSON.parse(String.bytesFrom(fragments[1], "base64url"));
		if (!claims.email || !claims.email_verified) {
			throw new Error(`invalid email: claims=${JSON.stringify(claims)}`);
		}

		// Sign user-name/email-addr with own key and store it in cookie.
		lib.cookie.set(r, {
			user: claims.email.split("@").shift(),
			email: claims.email,
		});
		r.log("Context Redirect");
		r.log(context.redirect);
		r.return(302, context.redirect);
	});
});

// `authHandler` is higher-order function, which receives `ruleFn`(function) that determines permissions,
// and returns a handler which blocks unauthorized users and redirect them to OpenID provider.
var authHandler = ruleFn => baseHandler(r => {
	var claims;

	var my_token="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJJbkV5RnVrQzdmRjQwRFlsWEpwNzV5NVRia1FkcjdGWl9PclAzUi1QSDc4In0.eyJqdGkiOiI0OWI1OWQxMS0wOGRhLTRjMDUtOWU0NS0xNGIxYjMxZWNhODQiLCJleHAiOjE2NDkzNzkxOTAsIm5iZiI6MCwiaWF0IjoxNjQ5Mzc4ODkwLCJpc3MiOiJodHRwczovL2F1dGgub2NwMDEudG9sbDYudGluYWEudGxhYnMuY2EvYXV0aC9yZWFsbXMvdGluYWEiLCJhdWQiOlsicmVhbG0tbWFuYWdlbWVudCIsInBsdGYtZXNkYi1kZXZlbG9wIiwibmV0YXBwcy1raWJhbmEtZGV2IiwibmFhZi1raWJhbmEiLCJyX09nWGlZVF9FcXg0cVhqeWVyS29BIiwicGx0Zi1wcmVwcm9kLXJhYmJpdG1xIiwiYWNjb3VudCIsInBsdGYtZGV2ZWxvcC1yYWJiaXRtcSIsIkdtRWRXeHJMNnAyIl0sInN1YiI6Ijc4Mjk5M2Y3LTJlZjktNDI3NC1iYjlmLTgyOWQ0MTQ2YmU1NyIsInR5cCI6IkJlYXJlciIsImF6cCI6Im5hYWYtcmFiYml0bXEtdGVzdG9hdXRocHJveHkiLCJhdXRoX3RpbWUiOjE2NDkzNzg4ODksInNlc3Npb25fc3RhdGUiOiI5NDBhNzE0ZC01OTJlLTQ5M2ItYTNiYi03NWYxYjZmNjAwODYiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbIm1hbmFnZS11c2VycyIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJuYWFmLXJhYmJpdG1xLXRlc3RvYXV0aHByb3h5Ijp7InJvbGVzIjpbInRlc3Ryb2xlIl19LCJwbHRmLWVzZGItZGV2ZWxvcCI6eyJyb2xlcyI6WyJwbHRmLWtpYmFuYS11c2VyIl19LCJuZXRhcHBzLWtpYmFuYS1kZXYiOnsicm9sZXMiOlsibWdtdF9yZWFkIiwibWdtdF93cml0ZSJdfSwibmFhZi1raWJhbmEiOnsicm9sZXMiOlsibmFhZi16ZXJvdG91Y2gta2liYW5hIl19LCJyX09nWGlZVF9FcXg0cVhqeWVyS29BIjp7InJvbGVzIjpbIm1nbXRfcmVhZCIsImFkbWluIiwibWdtdF93cml0ZSJdfSwicGx0Zi1wcmVwcm9kLXJhYmJpdG1xIjp7InJvbGVzIjpbInJhYmJpdG1xX3VpIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX0sInBsdGYtZGV2ZWxvcC1yYWJiaXRtcSI6eyJyb2xlcyI6WyJyYWJiaXRtcV91aSJdfSwiR21FZFd4ckw2cDIiOnsicm9sZXMiOlsiYXBwX3VzZXIiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJuYW1lIjoiTWljaGFlbCBYaW5nIiwicHJlZmVycmVkX3VzZXJuYW1lIjoieDIxNDA3NCIsImdpdmVuX25hbWUiOiJNaWNoYWVsIiwiZmFtaWx5X25hbWUiOiJYaW5nIiwiZW1haWwiOiJtaWNoYWVsLnhpbmdAdGVsdXMuY29tIn0.Qfn4mE8HksQccXqeVDDYf3hijJT1H7dN4crA_LqD-rgL_pyE-ZNSvoQWJRF6JQxIlyppKxBhoRonnpewmjl6jOs_aAmfZYrkvoNslPqNtpdfmqZQqOB-tZO61KYAwHgwIorA2JPvAyEWukcX2pIw62-qOaBNnFAU7bRaITZvZe5do7uu3tW3YA2zIu2kRAS8gjZAEOIqyTxHuSQFyRE-rCU2ftqVV_4BEslxCJuG1gE6T907-AylWQf6HqeyJZe0NciDGveIgXEpDT203z3jGxeM8Hy2RSdrF1FGm6GOJDyWeAPPbBgg_UwzzEvpi7KFd7Ci-_qzMXNOKt2__i79Zg";
	var fgts = my_token.split(".");
	var mc = JSON.parse(String.bytesFrom(fgts[1], "base64url"));
	r.log(JSON.stringify(mc));
	r.log("mc-------------------------------------------------------")
	r.log("After Claims");
	r.log(r.variables["query_string"]);
	r.log(r.variables["request_id"]);
	r.log(r.variables["scheme"]);
	r.log(r.variables["host"]);
	r.log(r.variables["request_uri"]);
	r.log("Before Try Claims");
	r.log("SOME TESTS");
	r.log(decodeURIComponent(r.variables["arg_code"]));
	r.log(r.variables["arg_code"]);
	r.log(r.variables["arg_query_string"]);
	r.log("END TESTS");

	try {
		claims = lib.cookie.get(r);
		if (!("email" in claims)) {
			throw new Error("not authorized yet");
		}
	} catch(e) {
		// Store `state` into cookie, which will be confirmed on oauth-callback endpoint.
		var reqId = r.variables["request_id"];
		lib.cookie.set(r, {
			state: reqId,
			redirect: r.variables["request_uri"],
		});
		
		// r.log("request_uri:")
		// r.log(r.variables["request_uri"])
		// r.return(302, `http://localhost:80`);
		// return;

		var query = {
			client_id: lib.oauthClient.getId(),
			// redirect_uri: `${r.variables["scheme"]}://${r.variables["host"]}/oauth2/callback`,
			redirect_uri: `${r.variables["scheme"]}://${r.variables["host"]}:8080/oauth2/callback`,
			response_type: "code",
			scope: "openid email",
			state: reqId,
		};
		r.log(query.redirect_uri)
		r.log("================")
		r.return(302, `https://accounts.google.com/o/oauth2/v2/auth?${lib.query.stringify(query)}`);

		r.log(`[authHandler] Redirected: error=${e}`);
		return;
	}

	// Check the user can access this application.
	if (!ruleFn(claims.email)) {
		printError(r, 403, `You cannot access this application. Email: ${claims.email}`);
		return;
	}

	// These variables below can read in nginx-configuration.
	r.variables["oidc_user"] = claims.user;
	r.variables["oidc_email"] = claims.email;
	r.variables["oidc_basic_auth"] = `${claims.user}:`.toUTF8().toString("base64");

	r.internalRedirect("@upstream");
});

export default {
	auth: authHandler,
	callback: callbackHandler,
};
