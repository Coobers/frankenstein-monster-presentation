/**
 * Created by COOBERS on 07.01.17.
 */
const express = require('express')
const session = require('express-session')
const bodyParser = require('body-parser')
const next = require('next')
const auth = require('./auth')
const AWS = require('aws-sdk');

const url = require('url')
const saltRounds = 10;
const myPlaintextPassword = 's0/\/\P4$$w0rD';
const someOtherPlaintextPassword = 'not_bacon';
const jwt    = require('jsonwebtoken');
const dev = process.env.NODE_ENV !== 'production'
const crypto = require('crypto');
const uuid = require('node-uuid');
const jsonxml = require('js2xmlparser');


const app = next({ dir: '.', dev })
const handle = app.getRequestHandler()
const superSecret = process.env.SUPER_SECRET;
const cookieParser = require('cookie-parser');

AWS.config.update({ "accessKeyId": process.env.AWS_KEY, "secretAccessKey": process.env.AWS_SECRET, "region": process.env.AWS_REGION });
console.log({ "accessKeyId": process.env.AWS_KEY, "secretAccessKey": process.env.AWS_SECRET, "region": process.env.AWS_REGION });
AWS.config.setPromisesDependency(require('bluebird'));


const dynamo = new AWS.DynamoDB();

app.prepare()
    .then(() => {
        const server = express();

        server.use(bodyParser.json())
        server.use(session({ secret: '!!Meow!!', resave: false, saveUninitialized: true }))
        server.use(auth.sessionSupport())
        server.use(auth.acceptToken({ successRedirect: '/' }))
        server.use(cookieParser());

        var apiRoutes = express.Router();

        apiRoutes.use(function(req, res, next) {

            var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.cookies.tokenoo;

            var home = req.url.match(/^\/$/);

            // all pages under /app must be authorized
            if(req.url.match(/^\/app\//) || req.url.match(/^\/_next\/pages\/app\//) || home){

                jwt.verify(token, superSecret, function(err, decoded) {
                    if (err) {
                        if(home){
                            return res.redirect('/login');
                        }
                        if (req.headers["x-requested-with"] == 'XMLHttpRequest') {
                            return res.status(403).json({ error: 'Failed to authenticate token.' });
                        }
                        return res.status(403).redirect('/login');
                    } else {
                        if(home){
                            return res.redirect('/app/dashboard');
                        }

                        return dynamo.getItem({
                            TableName: 'sessions',
                            Key: {
                                key: {
                                    'S': decoded.token
                                }
                            },
                        }).promise().then((result,data)=>{

                            if(!result || !result.Item || !result.Item.id || !result.Item.key){
                                return res.status(403).json({ error: 'Failed to authenticate.' });
                            }

                            req.decoded = decoded;
                            next();
                        }).catch(e=>{
                            return res.status(403).json({ error: 'Failed to authenticate 2.' });
                        });
                    }
                });
                return;
            }
            next();
        });
        server.use('/', apiRoutes);


        // returns user session data
        server.get('/me', (req, res) => res.json(req.user || null))

        server.get('*', (req, res) => {
            var urli = url.parse(req.url, true)

            // additional custom url handler

            handle(req, res)
        })

        server.listen(process.env.PORT || 5000, err => {
            if (err) throw err
            console.log('> Next-auth ready on http://localhost:'+(process.env.PORT || 5000))
        })
    })