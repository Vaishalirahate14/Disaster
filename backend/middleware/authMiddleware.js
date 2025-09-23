const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
require("dotenv").config();

// Middleware to protect routes
const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Attach user object to request (without password)
      req.user = await User.findById(decoded.id).select("-password");

      return next(); // Continue to next middleware or route
    } catch (error) {
      console.error(error);
      return res.status(401).json({ message: "Not authorized, token failed" });
    }
  }

  if (!token) {
    return res.status(401).json({ message: "Not authorized, no token" });
  }
};

// Middleware to check roles
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Not authorized, no user found" });
    }

    if (!roles.includes(req.user.role)) {
        return res
          .status(403)
          .json({ message: `User role '${req.user.role}' not authorized` });
    }

    next();
  };
};

module.exports = { protect, authorize };