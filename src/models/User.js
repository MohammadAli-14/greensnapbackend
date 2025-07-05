import mongoose from "mongoose";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import crypto from "crypto";

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
 email: {
  type: String,
  required: true,
  unique: true,
  validate: {
    validator: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
    message: "Invalid email format"
  }
},
  password: {
    type: String,
    minLength: [8, "Password must have at least 8 characters."],
    maxLength: [32, "Password cannot have more than 32 characters."],
    select: false,
  },
  accountVerified: { 
    type: Boolean, 
    default: false 
  },
  verificationCode: Number,
  verificationCodeExpire: Date,
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  resetPasswordOTP: Number,       // Added for OTP reset
  resetPasswordOTPExpire: Date,   // Added for OTP expiration
  cooldownExpires: Date,
  createdAt: {
    type: Date,
    default: Date.now,
  },
  resetPasswordResendCount: {
  type: Number,
  default: 0,
  min: 0
},
resetPasswordCooldownExpires: Date,
  profileImage: {
    type: String,
    default: ""
  },
  reportCount: {
    type: Number,
    default: 0
  },
  points: {
    type: Number,
    default: 0
  }, 
  resendCount: {
    type: Number,
    default: 0,
    min: 0
  },
  tokenVersion: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password
userSchema.methods.comparePassword = async function(userPassword) {
  return await bcrypt.compare(userPassword, this.password);
};

userSchema.methods.generateVerificationCode = function() {
  function generateRandomFiveDigitNumber() {
    const firstDigit = Math.floor(Math.random() * 9) + 1;
    const remainingDigits = Math.floor(Math.random() * 10000)
      .toString()
      .padStart(4, '0');

    return parseInt(firstDigit + remainingDigits);
  }
  
  const verificationCode = generateRandomFiveDigitNumber();
  this.verificationCode = verificationCode;
  this.verificationCodeExpire = Date.now() + 5 * 60 * 1000;

  return verificationCode;
};

// Generate JWT
userSchema.methods.generateToken = function() {
  return jwt.sign(
    { 
      userId: this._id,
      verified: this.accountVerified,
      tokenVersion: this.tokenVersion
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE }
  );
};

// Generate password reset token
userSchema.methods.generateResetPasswordToken = function() {
  const resetToken = crypto.randomBytes(20).toString("hex");

  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.resetPasswordExpire = Date.now() + 15 * 60 * 1000;

  return resetToken;
};

// Generate password reset OTP (Added method)
userSchema.methods.generateResetOTP = function() {
  // Generate a 5-digit OTP
  const otp = Math.floor(10000 + Math.random() * 90000);
  this.resetPasswordOTP = otp;
  // Set expiration to 5 minutes (300,000 milliseconds)
  this.resetPasswordOTPExpire = Date.now() + 5 * 60 * 1000;
  return otp;
};

userSchema.index({ reportCount: -1, points: -1 });
const User = mongoose.model("User", userSchema);

export default User;