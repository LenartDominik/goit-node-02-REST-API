const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const { userSchema } = require('./../../models/users');
const {
	findUserByEmail,
	findUserByID,
	checkUserExists,
	addUser,
} = require('./../../controllers/userOperations');
const tokenMiddleware = require('./../../middlewares/tokenMiddleware');

router.post('/signup', async (req, res, next) => {
	try {
		const { error } = userSchema.validate(req.body);

		if (error) {
			return res.status(400).json({ message: 'Field missing' });
		}

		const userExists = await checkUserExists(req.body.email);

		if (userExists) {
			return res.status(409).json({ message: 'Email in use' });
		}

		const hashedPassword = await bcrypt.hashSync(req.body.password, 10);

		const newUser = await addUser({
			email: req.body.email,
			password: hashedPassword,
		});

		res.status(201).json({
			user: {
				email: newUser.email,
				subscription: newUser.subscription,
			},
		});
	} catch (err) {
		res.status(500).json({ message: err.message });
	}
});

router.post('/login', async (req, res, next) => {
	if (!req.body.email || !req.body.password) {
		return res.status(400).json({ message: 'Field missing' });
	}

	const userData = await findUserByEmail(req.body.email);

	if (!userData) {
		return res.status(401).send({ message: 'Email or password is wrong' });
	}

	const hashVerifiedPassword = await bcrypt.compareSync(
		req.body.password,
		userData.password
	);

	if (!hashVerifiedPassword) {
		return res.status(401).send({ message: 'Email or password is wrong' });
	}

	const token = jwt.sign({ userId: userData._id }, process.env.ACCESS_TOKEN, {
		expiresIn: '1h',
	});
	userData.token = token;
	await userData.save();

	res.status(200).send({
		token: token,
		user: {
			email: userData.email,
			subscription: userData.subscription,
		},
	});
});

router.get('/logout', tokenMiddleware, async (req, res) => {
	try {
		const user = await findUserByID(req.user.userId);

		if (!user) {
			return res.status(401).json({ message: 'Not authorized' });
		}

		user.token = null;
		user.save();
		res.sendStatus(204);
	} catch (err) {
		res.status(500).json({ message: err.message });
	}
});

router.get('/current', tokenMiddleware, async (req, res) => {
	try {
		const user = await findUserByID(req.user.userId);

		if (!user) {
			return res.status(401).json({ message: 'Not authorized' });
		}
		res
			.status(200)
			.send({ email: user.email, subscription: user.subscription });

		console.log(user);
	} catch (err) {
		res.status(500).json({ message: err.message });
	}
});

module.exports = router;
