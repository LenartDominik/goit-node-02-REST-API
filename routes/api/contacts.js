const express = require('express');
const router = express.Router();
const {
	listContacts,
	getContactById,
	removeContact,
	addContact,
	updateContact,
	updateFavorite,
} = require('./../../controllers/contactOperations');

const {
	addContactSchema,
	updateContactSchema,
	favoriteSchema,
} = require('../../models/contacts');

// const {userSchema} = require("../../models/userModel");

router.get('/', async (_, res) => {
	try {
		const contacts = await listContacts();
		res.status(200).json(contacts);
	} catch (err) {
		console.warn(err.message);
	}
});

router.get('/:contactId', async (req, res) => {
	try {
		const contact = await getContactById(req.params.contactId);
		!contact
			? res.status(404).json({ message: 'Not found' })
			: res.status(200).json(contact);
	} catch (err) {
		console.warn(err.message);
	}
});

router.post('/', async (req, res) => {
	try {
		const { error } = addContactSchema.validate(req.body);
		console.log(error);
		if (error) {
			res.status(400).json({ message: 'missing required field' });
		} else {
			const newContact = await addContact(req.body);

			res.status(201).json(newContact);
		}
	} catch (err) {
		console.warn(err.message);
	}
});

router.delete('/:contactId', async (req, res) => {
	try {
		const contact = await removeContact(req.params.contactId);
		!contact
			? res.status(404).json({ message: 'Not found' })
			: res.status(200).json({ message: 'Contact deleted' });
	} catch (err) {
		console.warn(err.message);
	}
});

router.put('/:contactId', async (req, res) => {
	try {
		const { error } = updateContactSchema.validate(req.body);
		if (error) {
			res.status(400).json({ message: 'missing fields' });
		}

		const updatedContact = await updateContact(req.params.contactId, req.body);
		if (!updatedContact) {
			res.status(404).json({ message: 'not found' });
		}
		res.status(200).json(updatedContact);
	} catch (err) {
		console.warn(err.message);
	}
});

router.patch('/:contactId/favorite', async (req, res) => {
	try {
		const validation = favoriteSchema.validate(req.body);
		if (!req.body) {
			res.status(400).json({ message: 'missing field favorite' });
		}

		if (!validation) {
			res.status(400).json({ message: 'Incorrect value in a field favorite' });
		}

		const updatedFavorite = await updateFavorite(
			req.params.contactId,
			req.body
		);

		if (!updatedFavorite) {
			res.status(404).json({ message: 'Not found' });
		} else {
			res.status(200).json(updatedFavorite);
		}
	} catch (err) {
		console.warn(err.message);
	}
});

module.exports = router;
