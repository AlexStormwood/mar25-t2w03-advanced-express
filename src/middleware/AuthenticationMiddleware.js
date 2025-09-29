const { UserModel } = require("../database/entities/User");
const { generateJWT, validateJWT } = require("../utils/jwtFunctions");



/**
 * For a user to log in, they must provide basic email/pass auth.
 * This will find a user based on a provided email and password, 
 * and attach the found user to `request.authentication` for other middleware to use.
 * @author BigfootDS
 *
 * @async
 * @param {Request} request Standard ExpressJS request object.
 * @param {Response} response Standard ExpressJS response object.
 * @param {NextFunction} next Standard ExpressJS Next middleware caller.
 * @returns 
 */
async function verifyBasicUserAuth (request, response, next) {

	// Read the Authorization header from the incoming request.
	// Note that it's lowercase in our code here - that's just automatic!
	let authHeader = request.headers["authorization"] ?? null;

	// If no auth header provided, stop the request
	if (authHeader == null) {
		return next(new Error("No auth data detected on a basic login endpoint."));
	}

	// Confirm it's a Basic auth string, 
    // and store only the encoded string.
    if (authHeader.startsWith("Basic ")) {
        authHeader = authHeader.substring(5).trim();
    }
    console.log("Provided base64 auth string is: " + authHeader);

    // Decode the string.
    let decodedAuth = Buffer.from(authHeader, 'base64').toString('ascii');
    console.log("Decoded auth data is: " + decodedAuth);

    // Convert it into a usable object.
    let objDecodedAuth = {email: '', password: ''};
    objDecodedAuth.email = decodedAuth.substring(0, decodedAuth.indexOf(":"));
    objDecodedAuth.password = decodedAuth.substring(decodedAuth.indexOf(":") + 1);
    console.log(objDecodedAuth)

	// Check if a user exists for the given login email.
	let foundUser = await UserModel.findOne({email: objDecodedAuth.email});

	if (!foundUser || foundUser == null){
		return next(new Error("No user found for the given auth data."));
	}
	// Note the subtly-different error messages above and below here - 
	// We as devs can figure out if the email was wrong vs the password was wrong,
	// But we shouldn't tell a potential hacker that info!
	let doesPasswordMatch = await foundUser.isMatchingPassword(objDecodedAuth.password);
	if (!doesPasswordMatch){
		return next(new Error("No user matches the given auth data."));
	}

	// Set up some data for other middleware functions to use,
	// using the spread operator to respect any existing authentication data.
	request.authentication = {
		...request.authentication,
		id: foundUser.id,
		user: foundUser
	}

	// And that's it! We confirmed that a valid email and password were provided, 
	// so we can move on to other steps in the middleware chain.
	next();
}

async function createJwt (request, response, next){
	// If a user is attached to the request object, create a JWT for that user.
	// This can be handled in a bunch of different ways, but here, we will assume that
	// createJwt is used in a middleware chain _after_ verifyBasicUserAuth has been called.

	// If no user is available on the request, something went wrong in the server!
	if (!request.authentication?.user){
		return next (new Error("Something went wrong with your session, please sign out and log in again later."));
	}

	// Create a new JWT based on the user established earlier in the middleware chain.
	let newJwt = generateJWT(request.authentication.user);

	// Attach the new JWT for this user to the middleware chain, 
	// and also keep any existing request.authentication data in place.
	request.authentication = {
		...request.authentication,
		jwt: newJwt
	}

	// Move on - the API endpoint's final callback should handle actually sending the JWT back to the user!
	next();
}

async function verifyJwt (request, response, next) {
	// If a JWT is attached to the request object, allow the request to continue on.
	// Could also be nice to make a new JWT, since that would allow a user's session to extend longer
	// based on how frequently they use the app.

	// Per these docs, a JWT should typically be sent in on the request's authorization header as a bearer token:
	// https://www.jwt.io/introduction#how-json-web-tokens-work 
	// We could put the JWT wherever, doesn't really matter, but using those docs as a baseline is good too.
	// So, we'll check the auth header for a token!

	// Read the Authorization header from the incoming request.
	// Note that it's lowercase in our code here - that's just automatic!
	let authHeader = request.headers["authorization"] ?? null;

	// If no auth header provided, stop the request
	if (authHeader == null) {
		return next(new Error("No auth data detected on a basic login endpoint."));
	}

	// Confirm it's a Bearer auth string, 
    // and store only the encoded string.
    if (authHeader.startsWith("Bearer ")) {
        authHeader = authHeader.substring(7).trim();
    }
    console.log("Provided bearer token auth string is: " + authHeader);

	// Verifying a token can actually throw a variety of errors,
	// it's good to catch them properly for the user's sake.
	try {
		let tokenVerificationResult = await validateJWT(authHeader);

		// If all is good, no errors will be thrown.
		// It can be a good UX thing to make a new JWT for a user so their login session lasts longer,
		// so once we confirm that their existing JWT is good, we can make a new one:

		let fresherJwt = generateJWT(tokenVerificationResult.tokenUser);

		// Attach the new JWT to the request.authentication object,
		// and then our API endpoint's final callback should handle actually sending the new JWT back to the user!
		request.authentication = {
			...request.authentication,
			jwt: fresherJwt,
			id: tokenVerificationResult.tokenUser.id,
			user: tokenVerificationResult.tokenUser
		}
		// Aaaaaand move on!
		next();

	} catch (error) {
		// We can check for different errors based on their names, and the `jsonwebtoken` package
		// has some named errors that we can work with!
		// https://www.npmjs.com/package/jsonwebtoken#errors--codes
		if (error.name == "TokenExpiredError"){
			return next(new Error("Session expired, please log in again."));
		} else {
			return next(new Error("Something went wrong with the session, please sign out and log in again later."));
		}
	}
}

module.exports = {
	verifyBasicUserAuth, createJwt, verifyJwt
}