import ErrorHandler from "../middleware/error.js";
import { catchAsyncError } from "../middleware/catchAsyncError.js";
import User from "../models/User.js";
import { sendEmail } from "../utils/sendEmail.js";
import { sendToken } from "../utils/sendToken.js";
import { generateResetOTPTemplate } from '../utils/emailTemplates.js';
import crypto from "crypto";
import { 
  validateEmail,
  PROVIDER_RULES,
  verifyEmailDomain,
  isEducationalEmail
} from "../utils/validators.js";

export const register = catchAsyncError(async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    
    // Validate required fields
    if (!username || !email || !password) {
      return next(new ErrorHandler("All fields are required.", 400));
    }

    // Validate email format with provider-specific rules
    if (!validateEmail(email)) {
      const domain = email.split('@')[1]?.toLowerCase();
      
      // Check if it's a known provider with specific rules
      if (domain && PROVIDER_RULES[domain]) {
        return next(new ErrorHandler(`Invalid ${domain} address format`, 400));
      }
      
      return next(new ErrorHandler("Invalid email address format", 400));
    }

    // Verify domain existence through DNS
    const domainValid = await verifyEmailDomain(email);
    if (!domainValid) {
      return next(new ErrorHandler("Email domain doesn't exist", 400));
    }

    // Check for educational email (for future use)
    const isEducational = isEducationalEmail(email);
    console.log(`Educational email detected: ${isEducational} - ${email}`);

    // Check for existing verified user
    const existingUser = await User.findOne({ 
      email,
      accountVerified: true
    });

    if (existingUser) {
      return next(new ErrorHandler("Email is already registered.", 400));
    }
    
    // Enhanced: Prevent too many registration attempts within 24 hours
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const registrationAttempts = await User.countDocuments({
      email,
      accountVerified: false,
      createdAt: { $gt: twentyFourHoursAgo }
    });

    if (registrationAttempts >= 3) {
      return next(
        new ErrorHandler(
          "You have exceeded the maximum registration attempts. Please try again tomorrow.",
          400
        )
      );
    }

    // Create user profile
    const profileImage = `https://api.dicebear.com/7.x/avataaars/png?seed=${username}`;
    const userData = { username, email, password, profileImage };

    const user = await User.create(userData);
    const verificationCode = user.generateVerificationCode();
    await user.save();
    
    // Send verification email
    sendVerificationEmail(verificationCode, username, email, res);
    
  } catch (error) {
    console.error("Registration Error:", error);
    next(error);
  }
});

async function sendVerificationEmail(verificationCode, username, email, res) {
  try {
    const message = generateEmailTemplate(verificationCode, username);
    await sendEmail({ 
      email, 
      subject: "Your Verification Code", 
      message 
    });
    
    res.status(200).json({
      success: true,
      message: `Verification email sent to ${email}`
    });
  } catch (error) {
    console.error("Email sending error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to send verification email.",
    });
  }
}

function generateEmailTemplate(verificationCode, username) {
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1.0"
    />
    <title>GreenSnap Verification Code</title>
  </head>
  <body style="margin:0; padding:0; background-color:#f2f2f2;">
    <table
      width="100%"
      cellpadding="0"
      cellspacing="0"
      role="presentation"
      style="background-color:#f2f2f2; padding: 20px 0;"
    >
      <tr>
        <td align="center">
          <table
            width="600"
            cellpadding="0"
            cellspacing="0"
            role="presentation"
            style="background:#ffffff; border-radius:8px; overflow:hidden; font-family:Arial, sans-serif;"
          >

            <!-- Inline SVG Logo -->
            <tr>
              <td align="center" style="padding: 30px 0 10px;">
                <svg width="80" height="80" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                  <circle cx="50" cy="50" r="48" fill="#2e7d32" />
                  <path d="M50 20 C65 20, 80 35, 50 80 C20 35, 35 20, 50 20 Z" fill="#a5d6a7"/>
                </svg>
              </td>
            </tr>

            <!-- Title -->
            <tr>
              <td style="padding: 0 40px 10px; text-align:center;">
                <h1 style="margin:0; font-size:24px; color:#2e7d32;">
                  Your GreenSnap Verification Code
                </h1>
              </td>
            </tr>

            <!-- Greeting -->
            <tr>
              <td style="padding: 0 40px 20px; font-size:16px; color:#333;">
               <p style="margin:0;">Hello, ${username},</p>
                <p style="margin:10px 0 0;">
                  Thank you for signing up for <strong>GreenSnap</strong>. Please use the verification code below to confirm your email address:
                </p>
              </td>
            </tr>

            <!-- Code Display -->
            <tr>
              <td align="center" style="padding: 0 40px 30px;">
                <div
                  style="
                    display:inline-block;
                    font-size:32px;
                    font-weight:bold;
                    color:#2e7d32;
                    letter-spacing:4px;
                    padding:15px 25px;
                    border:2px dashed #2e7d32;
                    border-radius:6px;
                  "
                >
                  ${verificationCode}
                </div>
              </td>
            </tr>

            <!-- Expiry Notice -->
            <tr>
              <td style="padding: 0 40px 20px; font-size:14px; color:#666;">
                This code will expire in <strong>5 minutes</strong>. If you did not request this, simply ignore this email.
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="background-color:#f9f9f9; padding:20px 40px; font-size:12px; color:#999; text-align:center;">
                <p style="margin:0;">
                  © ${new Date().getFullYear()} GreenSnap, Inc. All rights reserved.
                </p>
                <p style="margin:8px 0 0;">
                  If you have any questions, feel free to contact us at
                  <a href="mailto:greensnapofficial@gmail.com">greensnapofficial@gmail.com</a>
                </p>
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
  </html>
  `;
}

export const verifyOTP = catchAsyncError(async (req, res, next) => {
  const { email, otp } = req.body;

  try {
    // Validate OTP format
    if (!otp || isNaN(Number(otp))) {
      return next(new ErrorHandler("Invalid OTP format", 400));
    }

    // Find unverified user
    const user = await User.findOne({ 
      email, 
      accountVerified: false 
    });

    if (!user) {
      return next(new ErrorHandler("No pending verification found. Please register first.", 404));
    }

    const numericOTP = Number(otp);

    // Verify OTP
    if (user.verificationCode !== numericOTP) {
      return next(new ErrorHandler("Invalid OTP code", 400));
    }

    // Check expiration
    const currentTime = Date.now();
    const expirationTime = user.verificationCodeExpire.getTime();
    
    if (currentTime > expirationTime) {
      return next(new ErrorHandler("OTP has expired. Please register again.", 400));
    }

    // Verify user account
    user.accountVerified = true;
    user.verificationCode = undefined;
    user.verificationCodeExpire = undefined;
    user.resendCount = 0;
    user.cooldownExpires = undefined;
    await user.save({ validateBeforeSave: false });

    // Send success response WITHOUT token
    res.status(200).json({
      success: true,
      message: "Account successfully verified!",
    });

  } catch (error) {
    console.error("OTP Verification Error:", error);
    next(new ErrorHandler("Internal Server Error", 500));
  }
});

export const resendOTP = catchAsyncError(async (req, res, next) => {
  const { email } = req.body;
  const MAX_RESEND_ATTEMPTS = 3;
  const COOLDOWN_HOURS = 24;

  // Validate email format using validator
  if (!email || !validateEmail(email)) {
    return next(new ErrorHandler("Invalid email address format", 400));
  }

  // Find unverified user
  const user = await User.findOne({ 
    email, 
    accountVerified: false 
  });

  if (!user) {
    return next(new ErrorHandler("No pending verification found for this email", 404));
  }

  // Combined check for max attempts AND active cooldown
  if (user.resendCount >= MAX_RESEND_ATTEMPTS && user.cooldownExpires && user.cooldownExpires > Date.now()) {
    const hoursLeft = Math.ceil((user.cooldownExpires - Date.now()) / (3600 * 1000));
    return next(new ErrorHandler(
      `Maximum attempts reached. Try again in ${hoursLeft} hours.`,
      429
    ));
  }

  // Check if cooldown is active (for cases below max attempts)
  if (user.cooldownExpires && user.cooldownExpires > Date.now()) {
    const minutesLeft = Math.ceil((user.cooldownExpires - Date.now()) / (60 * 1000));
    return next(new ErrorHandler(
      `Please try again in ${minutesLeft} minutes.`,
      429
    ));
  }

  // Reset counter if cooldown period has passed OR we're below max attempts
  if (user.resendCount >= MAX_RESEND_ATTEMPTS) {
    user.resendCount = 0;
  }

  // Generate new verification code and update resend count
  const verificationCode = user.generateVerificationCode();
  user.resendCount = (user.resendCount || 0) + 1;

  // Set cooldown if max attempts reached
  if (user.resendCount === MAX_RESEND_ATTEMPTS) {
    user.cooldownExpires = Date.now() + COOLDOWN_HOURS * 60 * 60 * 1000;
  } else {
    user.cooldownExpires = undefined;
  }

  await user.save({ validateBeforeSave: false });

  // Send email
  try {
    const message = generateEmailTemplate(verificationCode, user.username);
    await sendEmail({ 
      email, 
      subject: "Your New Verification Code", 
      message 
    });

    res.status(200).json({
      success: true,
      message: `New verification code sent to ${email}`
    });
  } catch (error) {
    console.error("Resend OTP email error:", error);
    
    // Rollback changes on email failure
    user.resendCount -= 1;
    if (user.resendCount < MAX_RESEND_ATTEMPTS) {
      user.cooldownExpires = undefined;
    }
    await user.save({ validateBeforeSave: false });
    
    return next(new ErrorHandler("Failed to resend OTP email", 500));
  }
});

export const login = catchAsyncError(async (req, res, next) => {
  const { email, password } = req.body;
  
  // Validate input
  if (!email || !password) {
    return next(new ErrorHandler("Email and password are required.", 400));
  }
  
  // Validate email format
  if (!validateEmail(email)) {
    return next(new ErrorHandler("Invalid email address format", 400));
  }
  
  // Find user
  const user = await User.findOne({ 
    email, 
    accountVerified: true 
  }).select("+password");
  
  if (!user) {
    return next(new ErrorHandler("Invalid email or password.", 400));
  }
  
  // Verify password
  const isPasswordMatched = await user.comparePassword(password);
  if (!isPasswordMatched) {
    return next(new ErrorHandler("Invalid email or password.", 400));
  }
  
  // Send token
  sendToken(user, 200, "User logged in successfully.", res);
});

export const logout = catchAsyncError(async (req, res, next) => {
  // Clear token from response
  res
    .status(200)
    .cookie("token", "", {
      expires: new Date(Date.now()),
      httpOnly: true,
      sameSite: "none",
      secure: true
    })
    .json({
      success: true,
      message: "Logged out successfully.",
    });
  
  // Add token invalidation logic
  const user = await User.findById(req.user._id);
  if (user) {
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save({ validateBeforeSave: false });
    
    console.log(`Token invalidated for user ${user.email}. New token version: ${user.tokenVersion}`);
  }
});

export const getUser = catchAsyncError(async (req, res, next) => {
  const user = req.user;
  res.status(200).json({
    success: true,
    user,
  });
});

export const forgotPassword = catchAsyncError(async (req, res, next) => {
  const MAX_RESEND_ATTEMPTS = 3;
  const COOLDOWN_HOURS = 24;
  
  const { email } = req.body;
  
  // Validate email format
  if (!email || !validateEmail(email)) {
    return next(new ErrorHandler("Invalid email address format", 400));
  }
  
  const user = await User.findOne({
    email,
    accountVerified: true,
  });
  
  if (!user) {
    return next(new ErrorHandler("User not found.", 404));
  }
  
  // Check and reset counter if cooldown expired
  if (user.resetPasswordResendCount >= MAX_RESEND_ATTEMPTS && 
      user.resetPasswordCooldownExpires < Date.now()) {
    user.resetPasswordResendCount = 0;
    user.resetPasswordCooldownExpires = undefined;
  }
  
  // Check if in cooldown period
  if (user.resetPasswordResendCount >= MAX_RESEND_ATTEMPTS) {
    const hoursLeft = Math.ceil((user.resetPasswordCooldownExpires - Date.now()) / (3600 * 1000));
    return next(new ErrorHandler(
      `You've reached maximum resend attempts. Try again in ${hoursLeft} hours.`,
      429
    ));
  }

  // Generate reset OTP
  const resetOTP = user.generateResetOTP();
  
  // Update resend counter
  user.resetPasswordResendCount = (user.resetPasswordResendCount || 0) + 1;
  
  // Set cooldown if max attempts reached
  if (user.resetPasswordResendCount === MAX_RESEND_ATTEMPTS) {
    user.resetPasswordCooldownExpires = Date.now() + COOLDOWN_HOURS * 60 * 60 * 1000;
  }
  
  await user.save({ validateBeforeSave: false });
  
  // Send email with OTP
  try {
    const message = generateResetOTPTemplate(resetOTP, user.username);
    await sendEmail({
      email: user.email,
      subject: "GreenSnap Password Reset OTP",
      message,
    });
    
    res.status(200).json({
      success: true,
      message: `Password reset OTP sent to ${user.email}`,
    });
  } catch (error) {
    console.error("Forgot Password Email Error:", error);
    
    // Revert changes on email failure
    user.resetPasswordOTP = undefined;
    user.resetPasswordOTPExpire = undefined;
    user.resetPasswordResendCount -= 1;
    
    if (user.resetPasswordResendCount < MAX_RESEND_ATTEMPTS) {
      user.resetPasswordCooldownExpires = undefined;
    }
    
    await user.save({ validateBeforeSave: false });
    
    return next(
      new ErrorHandler(
        error.message || "Failed to send reset password email",
        500
      )
    );
  }
});

export const verifyResetOTP = catchAsyncError(async (req, res, next) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return next(new ErrorHandler("Email and OTP are required.", 400));
  }

  // Validate email format
  if (!validateEmail(email)) {
    return next(new ErrorHandler("Invalid email address format", 400));
  }

  // Find user by email
  const user = await User.findOne({ email, accountVerified: true });
  
  if (!user) {
    return next(new ErrorHandler("User not found.", 404));
  }

  // Check if OTP matches
  if (user.resetPasswordOTP !== Number(otp)) {
    return next(new ErrorHandler("Invalid OTP code", 400));
  }

  // Check expiration
  if (user.resetPasswordOTPExpire <= Date.now()) {
    return next(new ErrorHandler("OTP has expired. Please request a new one.", 400));
  }

  // Clear OTP after verification
  user.resetPasswordOTP = undefined;
  user.resetPasswordOTPExpire = undefined;
  
  // Also reset rate-limiting counters
  user.resetPasswordResendCount = 0;
  user.resetPasswordCooldownExpires = undefined;
  
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    success: true,
    message: "OTP verified successfully.",
  });
});

export const resetPasswordWithOTP = catchAsyncError(async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      console.error("Reset password missing fields:", req.body);
      return next(new ErrorHandler("Email and password are required.", 400));
    }

    // Validate email format
    if (!validateEmail(email)) {
      return next(new ErrorHandler("Invalid email address format", 400));
    }

    const user = await User.findOne({ email, accountVerified: true });
    
    if (!user) {
      console.error("User not found for reset:", email);
      return next(new ErrorHandler("User not found.", 404));
    }

    // Update password
    user.password = password;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();

    // Send success response
    res.status(200).json({
      success: true,
      message: "Password has been reset successfully.",
    });
    
  } catch (error) {
    console.error("Password reset error:", error);
    next(new ErrorHandler("Internal Server Error", 500));
  }
});