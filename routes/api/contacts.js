const express = require('express');
const router = express.Router();
const Joi = require('joi');

const {
	listContacts,
	getContactById,
	removeContact,
	addContact,
	updateContact,
} = require('../../models/contacts');

const contactSchema = Joi.object({
	name: Joi.string().min(2).max(25).required(),
	email: Joi.string().email().lowercase().required(),
	phone: Joi.string().min(7).required(),
});

const updateContactSchema = Joi.object({
	name: Joi.string().min(2).max(20),
	email: Joi.string().email().lowercase(),
	phone: Joi.string().min(7),
}).min(1);

router.get('/', async (_, res) => {
	try {
		const contacts = await listContacts();
		res.status(200).json(contacts);
	} catch (err) {
		console.warn(err.message);
	}
});

router.get('/:contactId', async (req, res, next) => {
	try {
		const contact = await getContactById(req.params.contactId);
		!contact
			? res.status(404).json({ message: 'Not found' })
			: res.status(200).json(contact);
	} catch (err) {
		console.warn(err.message);
	}
});

router.post('/', async (req, res, next) => {
	try {
		const { error } = contactSchema.validate(req.body);
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

router.delete('/:contactId', async (req, res, next) => {
	try {
		const contact = await removeContact(req.params.contactId);
		!contact
			? res.status(404).json({ message: 'Not found' })
			: res.status(200).json({ message: 'Contact deleted' });
	} catch (err) {
		console.warn(err.message);
	}
});

router.put('/:contactId', async (req, res, next) => {
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

module.exports = router;
