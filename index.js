const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const jwtAuthz = require('express-jwt-authz');
const Appbase = require('appbase-js');
const fetch = require('node-fetch');

// middlewares
const app = express();
app.use(cors());
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
	extended: true
}));

const checkJwt = jwt({
	// Dynamically provide a signing key
	// based on the kid in the header and
	// the singing keys provided by the JWKS endpoint.
	secret: jwksRsa.expressJwtSecret({
		cache: true,
		rateLimit: true,
		jwksRequestsPerMinute: 5,
		jwksUri: 'https://divyanshu.auth0.com/.well-known/jwks.json',
	}),

	// Validate the audience and the issuer.
	audience: 'https://divyanshu.xyz',
	issuer: 'https://divyanshu.auth0.com/',
	algorithms: ['RS256']
});

// check if the user has write:todos scope
const checkWriteScope = jwtAuthz([ 'write:todos' ]);

const headers = (getAccessToken) => ({
	'content-type': 'application/json',
	accept: 'application/json',
	authorization: getAccessToken
});

const getUserInfo = (token) => {
	return fetch('https://divyanshu.auth0.com/userinfo', {
		headers: headers(token)
	})
		.then(res => res.json())
		.then(json => json)
		.catch(err => console.error(err))
}

const appbaseRef = new Appbase({
	url: "https://scalr.api.appbase.io",
	app: "todomvc-authorization",
	credentials: "176SVfLUy:79f592d0-8ad3-4c90-9280-9e2b5ccf481c"
});

const ES_TYPE = "todo_reactjs";

// resolve the promise if the user matches otherwise reject
const verifyCreatedBy = (user, todoId) => (
	new Promise((resolve, reject) => {
		appbaseRef.get({
			type: ES_TYPE,
			id: todoId
		}).on("data", function(response) {
			const data = response._source;
			// first verify if the creator of the todo is the same user
			if (data.createdBy !== user.email) {
				reject(false);
			}
			else {
				resolve(true);
			}
		}).on("error", function(err) {
			console.error(err);
			reject(false);
		})
	})
);

// routes
app.post('/', checkJwt, checkWriteScope, (req, res) => {
	getUserInfo(req.headers.authorization)
		.then((user) => {
			appbaseRef.index({
			  type: ES_TYPE,
			  id: req.body.id,
			  body: {
				id: req.body.id,
				title: req.body.title,
				completed: false,
				createdAt: req.body.createdAt,
				name: user.nickname,
				avatar: user.picture,
				createdBy: user.email
			  }
			}).on("data", function(response) {
			  res.send({
				  status: 200,
				  message: 'success'
			  });
			}).on("error", function(error) {
			  console.error(error);
			  res.send(error);
			})
		});
})

app.put('/', checkJwt, checkWriteScope, (req, res) => {
	getUserInfo(req.headers.authorization)
	.then(user => verifyCreatedBy(user, req.body.id))
	.then(() => {
		appbaseRef.update({
			type: ES_TYPE,
			id: req.body.id,
			body: {
				doc: Object.assign({},
					req.body.completed !== undefined && {
						completed: req.body.completed
					},
					req.body.title && {
						title: req.body.title
					})
			}
			}).on("data", function(response) {
				res.send({
					status: 200,
					message: 'success'
				});
			}).on("error", function(error) {
				console.error(error);
				res.send(error);
			})
	})
	.catch((err) => {
		console.error('verifyCreatedBy rejected promise', err);
		res.send({
			status: 401,
			message: 'unauthorized'
		});
	})
})

app.delete('/', checkJwt, checkWriteScope, (req, res) => {
	getUserInfo(req.headers.authorization)
	.then(user => verifyCreatedBy(user, req.body.id))
	.then(() => {
		appbaseRef.delete({
			type: ES_TYPE,
			id: req.body.id
		}).on("data", function(response) {
			res.send({
				status: 200,
				message: 'success'
			});
		}).on("error", function(error) {
			console.error(error);
			res.send(error);
		})
	})
	.catch((err) => {
		console.error('verifyCreatedBy rejected promise', err);
		res.send({
			status: 401,
			message: 'unauthorized'
		});
	})
})

app.listen(8000, () => {
	console.log('Node middleware listening on port 8000!');
});