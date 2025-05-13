const express = require('express');
const { StatusCodes } = require('http-status-codes');  
const User = require('../models/user');
const authenticateToken = require('../middleware/authenticationMiddleware');
const authenticated_user = express.Router();

authenticated_user.get('/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id)
        .select('firstName lastName email phoneNumber address -_id'); 
    if (!user) 
        return res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found' });
    res.status(StatusCodes.OK).json(user);
});

authenticated_user.post('/logout', authenticateToken, (req,res) => {
    res.clearCookie('token', {
        httpOnly: true,
        sameSite: 'none',
        secure: true
    });
    res.status(StatusCodes.OK).json({ message: 'Logged out successfully' });
});

module.exports = authenticated_user;  