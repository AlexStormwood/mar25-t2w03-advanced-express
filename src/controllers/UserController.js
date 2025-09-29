const express = require("express");
const { verifyBasicUserAuth, createJwt, verifyJwt } = require("../middleware/AuthenticationMiddleware");
const { UserModel } = require("../database/entities/User");
const { generateJWT } = require("../utils/jwtFunctions");
const router = express.Router();

// No middleware needed - simple route!
// We'll just process the user's signup here in the route callback handler.
router.post(
	"/register",
	async (request, response, next) => {
		// We could use request.body directly,
		// but it's a safer habit to make a clone of an object
		// to do things like sanitisation and modification of that data.
		let newUserData = {...request.body};
		
		// Basic validation stuff, you can do more complex validation elsewhere:
		if (
			newUserData.email?.length <= 3 ||
			newUserData.password?.length <= 8
		){
			return next(new Error("Invalid user registration data provided."));
		}


		try {
			// Make a user in the database.
			let newUser = await UserModel.create({
				email: newUserData.email,
				password: newUserData.password
			});

			// Then, make a JWT to represent that user being logged-in.
			// They've just signed up, of course they're logged in! ;) 
			let newUserJwt = generateJWT(newUser);

			// Send the results back to the front-end.
			response.json({
				data: newUser,
				jwt: newUserJwt
			});

		} catch (error) {
			// General handler for any error in the above code.
			return next(new Error(error.message));
		}
	}
)

// This route requires a user to exist in the database already,
// and uses the verifyBasicUserAuth middleware to do that.
// When the user logs in, the API confirms their data and
// returns a JWT for that user's login session. 
router.post(
	"/login", 
	verifyBasicUserAuth, 
	createJwt,
	async (request, response, next) => {

		// The middleware have done all of the heavy lifting,
		// so we can just send a variable that should've been
		// assigned as part of one of those middleware steps!
		response.json({
			jwt: request.authentication.jwt
		});
	}
);

// This route retrieves different data depending on
// who is being represented in the JWT.
// Users searching for their own data get their full data.
// Users searching for someone else's data get stripped-down results,
// for security purposes.
router.get(
	"/:targetUserId",
	verifyJwt,
	async (request, response, next) => {
		// Some mild logic needed - we don't want a user's entire data,
		// such as their password (even when hashed and salted) to be sent out.
		// The verifyJwt middleware step just ensures that a user is logged in when viewing this route.
		// It does not verify that the user is viewing their own information.
		// We could make middleware to do that, and should do that in a larger app, but...
		// we can keep things small here.

		if (request.authentication.id == request.params.targetUserId){
			// We can be a bit cheeky and optimised here - 
			// the verifyJwt function already searched the DB for one user.
			// If that user is viewing themselves, we don't need to make another DB request.
			// Just send back the data that we already found earlier.
			response.json({
				data: request.authentication.user
			});
		} else {
			// If the logged-in user is viewing some other user's data,
			// then we need to make a new DB query.
			// We can also use this chance to restrict the query and
			// only return certain fields on the user, 
			// this will let us omit the password from the returned query results.

			let result = await UserModel.findById(request.params.targetUserId).select({ password: 0, salt: 0});
			// 1 is true, 0 is false. By default, all document fields are included in query results.
			// So specifying 0 is an easy way to exclude or omit just specific fields.
			// Alternate syntax:
			// let result = await UserModel.findById(request.params.targetUserId).select("-password -salt");

			response.json({
				data: result
			});
		}
	}
);