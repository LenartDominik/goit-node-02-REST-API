const Contact = require('./../models/contactModel');

const listContacts = async () => {
	return await Contact.find();
};

const getContactById = async (contactId) => {
	return await Contact.findById(contactId);
};

const removeContact = async (contactId) => {
	return await Contact.deleteOne({ _id: contactId });
};
const addContact = async (body) => {
	return await Contact.create(body);
};

const updateContact = async (contactId, body) => {
	return await Contact.findByIdAndUpdate(contactId, body);
};

const updateFavorite = async (contactId, body) => {
	return await Contact.findByIdAndUpdate(contactId, body);
};

module.exports = {
	listContacts,
	getContactById,
	removeContact,
	addContact,
	updateContact,
	updateFavorite,
};