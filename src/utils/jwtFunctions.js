const jwt = require("jsonwebtoken");
const { UserModel } = require("../database/entities/User");



/**
 * Creates a JWT based on a given instance of a User model.
 * 
 * JWTs made in this function will expire after 24 hours.
 * 
 * @author BigfootDS
 *
 * @param {UserModel} targetUser Instance of a User model document from MongooseJS.
 * @returns {string} JSON string representing the freshly-made JWT of the user.
 */
function generateJWT(targetUser){
	let tokenBody = {
		userId: targetUser.id
	}

	if (!process.env.JWT_SECRET) {
		throw new Error("Server environment configuration failure on token creation.");
	}

	let freshJwt = jwt.sign(
		// Custom payload data, should be an object containing whatever JSON data you want.
		tokenBody,
		// JWT secret key, should come from the environment variables.
		process.env.JWT_SECRET,
		// JWT standard data such as its expiration time, 
		{
			expiresIn: "1d"
		}
	);

	return freshJwt;

	/*
	A short version of the above is just:

	return jwt.sign({tokenBody, process.env.JWT_SECRET, {expiresIn: "1d"}});
	
	Note the position of the parameters there - there's three, they must be set in the correct order! 
	And note how we definitely always want our tokens to expire eventually!
	*/
}



/**
 * Returns an object and user for a given JWT, if the JWT is valid.
 * @author BigfootDS
 *
 * @async
 * @param targetJwt 
 * @returns {Promise<{decodedValidToken: object, tokenUser: object}}
 */
async function validateJWT(targetJwt){
	if (!process.env.JWT_SECRET) {
		throw new Error("Server environment configuration failure on token validation.");
	}

	// Synchronously confirm if the JWT is legitimate AND hasn't expired yet:
	let validJwt = jwt.verify(targetJwt, process.env.JWT_SECRET);
	console.log(JSON.stringify(validJwt, null, 4));

	// Confirming that a JWT is valid is one thing, but...
	// Did a hacker just make a random JWT? Or do we have a JWT from a real user?
	// We should search for a user based on the data we're expecting the JWT to contain!
	let tokenUser = await UserModel.findOne({_id: validJwt.validJwt.userId});

	if (!tokenUser || tokenUser == null){
		throw new Error("User not found for provided token.");
	}

	return {
		decodedValidToken: validJwt,
		tokenUser: tokenUser
	}
}


// This function is kinda optional - 
// it's more for the ability to still read a JWT
// even when the JWT is invalid.
// Not typically used directly as part of authentication processes, but good to inject when debugging an error.
function decodeJWT(targetJwt){
	return jwt.decode(targetJwt);
}

module.exports = {
	generateJWT, validateJWT, decodeJWT
}