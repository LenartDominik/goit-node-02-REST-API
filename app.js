const express = require('express');
const logger = require('morgan');
const cors = require('cors');
const mongoose = require('mongoose');

const contactsRouter = require('./routes/api/contacts');
require('dotenv').config();
const uriDb = process.env.DB_URI;

console.log(uriDb);

const connection = mongoose.connect(uriDb, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});

connection
	.then(() => {
		console.log('Database connection successful');
	})
	.catch((e) => {
		console.error(e.message);
		process.exit(1);
	});

const app = express();

const formatsLogger = app.get('env') === 'development' ? 'dev' : 'short';

app.use(logger(formatsLogger));
app.use(cors());
app.use(express.json());

app.use('/api/contacts', contactsRouter);

app.use((req, res, next) => {
	res.status(404).json({ message: 'Not found' });
});

app.use((err, req, res, next) => {
	if (err.message === 'Contact not found') {
		res.status(404).json({ message: 'Not found' });
	} else {
		res.status(500).json({ message: err.message });
	}
});

module.exports = app;
