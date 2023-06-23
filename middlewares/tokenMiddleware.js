const jwt = require('jsonwebtoken');

const tokenMiddleware = async (req, res, next) => {
	try {
		const token = req.headers.authorization?.split(' ')[1];
		if (!token) {
			return res.status(401).json({ message: 'Not authorized' });
		}
		const data = jwt.verify(token, process.env.ACCESS_TOKEN);
		req.user = data;
		next();
	} catch (err) {
		if (err.name === 'JsonWebTokenError') {
			return res.status(403).json({ message: 'Invalid token' });
		}
		return next(err);
	}
};

module.exports = tokenMiddleware;
