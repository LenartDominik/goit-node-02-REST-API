
const jwt = require('jsonwebtoken');
const tokenMiddleware = async (req, res, next) => {
	const token = req.headers.authorization?.split(' ')[1];
	if (!token) {
		return res.sendStatus(401).json({ message: 'Not authorized' });
	}
	jwt.verify(token, process.env.ACCESS_TOKEN, (err, data) => {
		if (err) {
			return res.sendStatus(403).send();
		}
		req.user = data;
		next();
	});
};
module.exports = tokenMiddleware;