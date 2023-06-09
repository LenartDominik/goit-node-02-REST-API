const fs = require('fs').promises;
const path = require('path');
const { nanoid } = import('nanoid');

const contactsPath = path.join(__dirname, './contacts.json');
const listContacts = async () => {
	try {
		const data = await fs.readFile(contactsPath);
		return JSON.parse(data);
	} catch (err) {
		console.warn(err.message);
	}
};
const getContactById = async (contactId) => {
	try {
		const contacts = await listContacts();
		return contacts.find(({ id }) => id === contactId);
	} catch (err) {
		console.warn(err.message);
	}
};
async function updateDataFile(instance) {
	try {
		fs.writeFile(contactsPath, JSON.stringify(instance, null, 2));
	} catch (err) {
		console.warn(err.message);
	}
}

const removeContact = async (contactId) => {
	try {
		const contacts = await listContacts();
		const index = contacts.findIndex((contact) => contact.id === contactId);
		if (index !== -1) {
			const updatedList = contacts.filter(({ id }) => id !== contactId);
			updateDataFile(updatedList);
			return updatedList;
		} else {
			return null;
		}
	} catch (err) {
		console.warn(err.message);
	}
};
const addContact = async (body) => {
	try {
		const newContact = { id: nanoid(), ...body };
		const contacts = await listContacts();
		const updatedList = [...contacts, newContact];
		updateDataFile(updatedList);
		return newContact;
	} catch (err) {
		console.warn(err.message);
	}
};
const updateContact = async (contactId, body) => {
	const contacts = await listContacts();
	const contactIndex = contacts.findIndex(
		(contact) => contact.id === contactId
	);
	if (contactIndex !== -1) {
		contacts[contactIndex] = { ...contacts[contactIndex], ...body };
		updateDataFile(contacts);
		return contacts[contactIndex];
	} else {
		return null;
	}
};

module.exports = {
	listContacts,
	getContactById,
	removeContact,
	addContact,
	updateContact,
};
