import acl from "js/acl.js";
import baseHandler from "js/baseHandler.js";

var callbackHandler = baseHandler.callback;

var callbackHandler3 = baseHandler.callback3;

var everyoneAuthHandler = baseHandler.auth(email => {
	var domain = email.split("@").pop();
	return acl.everyoneDomains.some(allowed => allowed === domain);
});

var employeeAuthHandler = baseHandler.auth(email => {
	var domain = email.split("@").pop();
	return acl.employeeDomains.some(allowed => allowed === domain);
});

var administratorAuthHandler = baseHandler.auth(email => {
	return acl.administratorAddresses.some(allowed => allowed === email);
});


export default {
	callbackHandler: callbackHandler,
	callbackHandler3: callbackHandler3,
	everyoneAuthHandler: everyoneAuthHandler,
};