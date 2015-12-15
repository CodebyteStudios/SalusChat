var app = require('express')(),
    serveStatic = require('serve-static'),
    bodyParser = require('body-parser'),
    db = require('diskdb'),
    openpgp = require('openpgp'),
    crypto = require('crypto'),
    fs = require('fs');

// make sure the db folder exists
if (!fs.existsSync(__dirname + '/db')) {
	fs.mkdirSync(__dirname + '/db');
}

// creates a hash from a random string using crypto.randomBytes, a UNIX timestamp, and
// crypto.createHash('md5'), then checks to see if a message with that hash exists in the database
function GenerateUniqueHash() {

	while(true) {

		var hash = crypto.createHash('md5').update(
			crypto.randomBytes(10).toString('hex') + "" + new Date().getTime()
		).digest('hex');

		if(!db.messages.findOne({"hash": hash})) {
			return hash;
		}
	}

}

function Envelope(res, meta, data) {

	if(!meta) meta = {};
	if(!data) data = {};

	res.send(JSON.stringify({
		"meta": meta,
		"data": data
	}));
}

db.connect(__dirname + '/db', ['users', 'messages']);

app.use(serveStatic(__dirname + '/public'));

app.use(bodyParser.json());

// join this server
app.post('/j', function(req, res) {

	if(!req.body.username || !req.body.key) {

		var missingParams = [];

		if(!req.body.username) missingParams.push("'username'");
		if(!req.body.key) missingParams.push("'key'");

		return Envelope(res, {
			"code": 400,
			"error": {
				"type": "Query",
				"message": "Missing field" + (missingParams.length > 1 ? "'s" : "") + ": " + missingParams.join(" and ")
			}
		});
	}

	var user = db.users.findOne({username: req.body.username});

	if(user) {

		return Envelope(res, {
			"code": 409,
			"error": {
				"type": "Query",
				"message": "Username in use"
			}
		});

	}
	else {

		if(db.users.save({
			"username": req.body.username,
			"key": req.body.key
		})) {

			return Envelope(res, {
				"code": 200
			});

		}

	}

});

// obtain users public key
app.post('/k', function(req, res) {

	if(!req.body.username) {
		return Envelope(res, {
			"code": 422,
			"error": {
				"type": "Query",
				"message": "Missing field 'username'"
			}
		});
	}

	// find the user with the username
	var user = db.users.findOne({username: req.body.username});

	// if we find the user send the username and key back to the client
	if(user) {

		return Envelope(res, {
			"code": 200
		}, {
			"username": user.username,
			"key": user.key
		});
	}
	// otherwise we send back an error stating the user doesn't exist
	else {
		return Envelope(res, {
			"code": 404,
			"error": {
				"type": "Database",
				"message": "User does not exist"
			}
		});
	}

});

// schedule a message to be sent to another user
app.post('/m', function(req, res) {

	if(!req.body.sender || !req.body.receiver || !req.body.message) {

		var missingParams = [];

		if(!req.body.sender) missingParams.push("'sender'");
		if(!req.body.receiver) missingParams.push("'receiver'");
		if(!req.body.message) missingParams.push("'message'");

		return Envelope(res, {
			"code": 400,
			"error": {
				"type": "Query",
				"message": "Missing field" + (missingParams.length > 1 ? "'s" : "") + ": " + missingParams.join(" and ")
			}
		});
	}

	// find the two users with the username
	var sender = db.users.findOne({username: req.body.sender}),
		receiver = db.users.findOne({username: req.body.receiver});

	// the user's exist, we now store the message and return the message encrypted
	// with the 'from' user's public key and a random hash the 'from' user will then
	// need to call /v to verify it's actually who's sending the message, which will
	// result in the message being marked receivable by the 'to' user
	if(sender && receiver) {

		var hash = GenerateUniqueHash();

		db.messages.save({
			"sender": req.body.sender,
			"receiver": req.body.receiver,
			"message": req.body.message,
			"hash": hash,
			"receivable": false
		});

		var publicKey = openpgp.key.readArmored(sender.key);

		openpgp.encryptMessage(publicKey.keys, hash).then(function(pgpMessage) {

			Envelope(res, {
				"code": 200
			}, {
				"pgpHash": pgpMessage
			});

		}).catch(function(error) {

			Envelope(res, {
				"code": 500,
				"error": {
					"type": "Encryption",
					"message": "The server was unable to encrypt the message with the senders public key"
				}
			});

		});

	}
	// otherwise we send back an error stating the user/user's don't exist
	else {

		var missingUsers = [];

		if(!sender) missingUsers.push("'sender'");
		if(!receiver) missingUsers.push("'from'");

		return Envelope(res, {
			"code": 404,
			"error": {
				"type": "Database",
				"message": "User" + ((missingUsers.length > 1) ? "'s do" : 'does') + "  not exist: " + missingUsers.join(" and ")
			}
		});
	}

});

// verify message and send it
app.post('/v', function(req, res) {

	if(!req.body.message) {
		return Envelope(res, {
			"code": 400,
			"error": {
				"type": "Query",
				"message": "Missing field 'message'"
			}
		});
	}

	var message = db.messages.findOne({"hash": req.body.message, "receivable": false});

	if(message) {

		db.messages.update({"_id": message._id}, {"receivable": true});

		return Envelope(res, {
			"code": 200
		});

	}
	else {

		return Envelope(res, {
			"code": 404,
			"error": {
				"type": "Database",
				"message": "Message with that hash does not exist"
			}
		});

	}

});

// retrieve all receivable messages for the passed username
app.post('/r', function() {

	if(!req.body.username) {
		return Envelope(res, {
			"code": 400,
			"error": {
				"type": "Query",
				"message": "Missing field 'username'"
			}
		});
	}

	var user = db.users.findOne({"username": req.body.username});

	if(user) {

		var promises = [];
		var publicKey = openpgp.key.readArmored(user.key);
		var messages = db.messages.find({"receiver": user.username, "receivable": true});

		// encode all the message hashes so that only the real user can mark them for removal later
		messages.forEach(function(message) {

			// these values are only used internally
			delete message._id;
			delete message.receivable;

			promises.push(new Promise(function(resolve, reject) {

				var hash = GenerateUniqueHash();

				db.messages.update({"_id": message._id}, {"hash": hash});

				openpgp.encryptMessage(publicKey.keys, hash).then(function(pgpMessage) {

					message.pgpHash = pgpMessage;

					resolve();

				}).catch(function(error) {

					reject();

				});

			}));

		});

		Promise.all(promises).then(function() {

			Envelope(res, {
				"code": 200
			}, {
				"messages": messages
			});

		}, function() {

			Envelope(res, {
				"code": 500,
				"error": {
					"type": "Encryption",
					"message": "The server was unable to encrypt the messages with the users public key"
				}
			});

		});

	}

});

// sets the lifetime of all the messages with the passed resolved pgpHash's to zero
// this will cause them to be removed upon the next server message garbage collection
app.post('/d', function() {

});

app.listen(process.argv[2]);
