const { AuthenticationError } = require("apollo-server");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");

module.exports = (context) => {
  //context = {....headers}
  const authHeader = context.req.headers.authorization;
  if (authHeader) {
    //Bearer
    const token = authHeader.split("Bearer ")[1];
    if (token) {
      try {
        const user = jwt.verify(token, SECRET_KEY);
        return user;
      } catch (err) {
        throw new AuthenticationError("Invalid /Expried token");
      }
    } //end 2

    throw new Error("Authentication token must be 'Bearer [token]");
  } ///end 1 if
  throw new Error("Authorization header must be provided");
};
