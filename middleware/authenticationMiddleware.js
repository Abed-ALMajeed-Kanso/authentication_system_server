const jwt = require('jsonwebtoken');
const { StatusCodes } = require('http-status-codes');

const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;

    if (!token){
        if (req.path === '/check-auth') {
            return res.status(StatusCodes.OK).json({
                authenticated: true,
            });
        }
        return res.status(StatusCodes.OK).json({ message: 'Access Denied. No token provided.'});
    }
        

    try {
        const decoded = jwt.verify(token, 'access');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(StatusCodes.FORBIDDEN).json({ message: 'Invalid or expired token.' });
    }
};

module.exports = authenticateToken;
