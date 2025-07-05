import express from "express";
import { 
  register,
  verifyOTP,
  resendOTP,
  login,
  logout,
  getUser,
  forgotPassword,
  verifyResetOTP,
  resetPasswordWithOTP
} from "../controllers/userController.js";
import { isAuthenticated } from "../middleware/auth.js";
import { sanitizeInput } from "../middleware/sanitize.js"; // Import sanitize middleware

const router = express.Router();

// Apply sanitizeInput middleware to all routes that handle email input
router.post("/register", sanitizeInput, register);
router.post("/verifyOTP", sanitizeInput, verifyOTP);
router.post("/resendOTP", sanitizeInput, resendOTP);
router.post("/login", sanitizeInput, login);
router.post("/logout", isAuthenticated, logout);
router.get("/me", isAuthenticated, getUser);
router.post("/password/forgot", sanitizeInput, forgotPassword);
router.post("/password/verify-otp", sanitizeInput, verifyResetOTP);
router.put("/password/reset", sanitizeInput, resetPasswordWithOTP);

export default router;