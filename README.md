# mar25-t2w03-advanced-express
Middleware, git collab practice, authentication and authorisation.



`node --watch-path=./ --watch-preserve-output ./src/index.js` is equivalent to `nodemon ./src/index.js`, and has been a stable feature since Node 20 and 22 

`node --env-file-if-exists=.env ./src/index.js` is the built-in way to process a .env file now, no need for dotenv for default usage.


# Auth Plans

- User model in Mongoose needs a pre-save hook ensure passwords are hashed and salted
	- Validators _should_ be implemented on the User model for things like password length as well
	- A property that is either a simple boolean for things like "isAdmin" or a foreign key reference to a Role model _should_ be implemented to implement authorization
- Middleware to validate base username/email + password authentication must be implemented
- Middleware to validate JWTs must be implemented


# Contributors

- [AlexStormwood](https://github.com/AlexStormwood)
- [NhiHuynh](https://github.com/lulu-codes)
- [JordanLeal-Walker](https://github.com/jordanleal12)
- [Joss Raine](https://github.com/truth-josstice)
- [DiosOne](https://github.com/DiosOne)
- [maxmoeller-147](https://github.com/maxmoeller-147)
- [Quinn Ma'aelopa](github.com/quinnsm97)
- [George Vasiliadis](https://github.com/GVasing)
- [KateMendoza](https://github.com/DellieKate)


