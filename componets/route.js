import express from 'express';
import bcrypt from 'bcrypt';
import UserModel from './model.js';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
const router = express.Router();

// SignUp
router.post('/', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const user = await UserModel.findOne({ email });
    if (user) {
      return res.json({ status: false, message: 'User already exists' });
    }

    if (!username || !email || !password) {
      return res.json({ status: false, message: 'Please fill all the fields' });
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = new UserModel({
      username,
      email,
      password: hashPassword,
    });

    await newUser.save();
    return res.json({ status: true, message: 'Record registered' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ status: false, message: 'Internal server error' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.json({ status: false, message: 'Please fill all the fields' });
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.json({ message: 'User is not registered', status: false });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.json({ message: 'Password is incorrect' });
    }

    const token = jwt.sign({ id: user._id }, process.env.KEY, { expiresIn: '5m' });
    res.cookie('token', token, { httpOnly: true, maxAge: 2592000000 });
    return res.json({ status: true, message: 'Login successful' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ status: false, message: 'Internal server error' });
  }
});

// Forgot Password - Send OTP
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.json({ status: false, message: 'User not registered' });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiration = Date.now() + 5 * 60 * 1000; // OTP valid for 5 minutes

    // Update user document with resetPasswordOTP
    user.resetPasswordOTP = {
      otp,
      expires: otpExpiration,
    };
    await user.save();

    // Send OTP via email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL, // Your email address
        pass: process.env.EMAIL_PASSWORD, // Your email password (consider using environment variables for security)
      },
    });

    const mailOptions = {
      from: process.env.EMAIL, // Sender email address
      to: email, // Recipient email address
      subject: 'Reset Password OTP',
      text: `Your OTP for password reset is ${otp}`, // Email body
    };

    await transporter.sendMail(mailOptions);
    return res.json({ status: true, message: 'OTP sent for password reset' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    return res.status(500).json({ status: false, message: 'Error sending OTP' });
  }
});


// Reset Password - Verify OTP and Update Password
router.post('/verify-otp', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.json({ status: false, message: 'User not registered' });
    }

    const storedOTP = user.resetPasswordOTP;
    if (!storedOTP || storedOTP.otp !== otp || Date.now() > storedOTP.expires) {
      return res.json({ status: false, message: 'Invalid or expired OTP' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password and clear OTP
    user.password = hashedPassword;
    user.resetPasswordOTP = undefined;
    await user.save();

    return res.json({ status: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).json({ status: false, message: 'Error resetting password' });
  }
});

// Middleware to verify user's token
const verifyUser = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.json({ status: false, message: 'No token provided' });
    }
    const decoded = jwt.verify(token, process.env.KEY);
    req.user = decoded;
    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({ status: false, message: 'Internal server error', error: error.message });
  }
};

// Verify route
router.get('/verify', verifyUser, (req, res) => {
  return res.json({ status: true, message: 'Authorized' });
});

// Logout route
router.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ status: true, message: 'Logged out successfully' });
});

export { router as UserRouter };
