const express = require("express");
const router = express.Router();
const { registerUser, loginUser, getUserProfile } = require("../controllers/userController");
const { protect } = require("../middleware/authMiddleware");

// @route   POST /api/users/register
// @desc    Register a new user (Student, Parent, Teacher, SchoolAdmin, NDMA)
// @route   POST /api/auth/register
// router.post("/auth/register", registerUser); // Already handled in server.js

// @route   POST /api/users/login
// @desc    Login user and return token
// @route   POST /api/auth/login
// router.post("/auth/login", loginUser); // Already handled in server.js

// @route   GET /api/users/profile
// @desc    Get logged-in user profile (protected route)
router.get("/profile", protect, getUserProfile);

module.exports = router;