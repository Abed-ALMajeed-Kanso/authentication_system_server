const express = require('express');
const { StatusCodes } = require('http-status-codes');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/user');
const { loginLimiter } = require('../middleware/ratelimiter');
const authenticateToken = require('../middleware/authenticationMiddleware');
const public_user = express.Router();

public_user.post('/login', loginLimiter, async (req, res) => {
    const { email, password, rememberMe } = req.body;

    if (!email || !password) 
        return res.status(StatusCodes.BAD_REQUEST).json({ message: 'Email and password required' });

    const user = await User.findOne({ email });

    console.log(user);

    if (!user) 
        return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid credentials' });
    

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch){
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid credentials' });

    }
        
    const token = jwt.sign({ id: user._id, email: user.email }, 'access', {
        expiresIn: rememberMe ? '2h' : '30m'
    });

    res.cookie('token', token, {
        httpOnly: true,
        secure: true, 
        sameSite: 'lax',
        maxAge: rememberMe ? 2 * 60 * 60 * 1000 : 30 * 60 * 1000 // 2 hours with remember_me, else 30 minutes
    });

    res.status(StatusCodes.OK).json({ message: 'Login successful' });
});

public_user.get('/check-auth', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id).select('firstName lastName email');
  
  if (!user) {
    return res.status(StatusCodes.NOT_FOUND).json({
      authenticated: false,
      message: 'User not found',
    });
  }

  return res.status(StatusCodes.OK).json({
    authenticated: true,
    user,
  });
});

module.exports = public_user;
