const express = require('express');
const { StatusCodes } = require('http-status-codes');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/user');
const public_user = express.Router();
// const { loginLimiter } = require('../middleware/ratelimiter');


public_user.post('/login', async (req, res) => {
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
        sameSite: 'none',
        maxAge: rememberMe ? 2 * 60 * 60 * 1000 : 30 * 60 * 1000 // 2 hours with remember_me, else 30 minutes
    });

    res.status(StatusCodes.OK).json({ message: 'Login successful' });
});

module.exports = public_user;
