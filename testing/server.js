/*
    NEEDS TO BE UPDATED AFTER EVERY NEW DEPENDENCY ADDED TO INDEX.JS
*/
const express = require('express');
const app = express(); 
const passport = require('passport');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");

require('../config/passport')(passport);
const router = require('../index').router;
const limiter = rateLimit({
    windowMs: 1 * 1000, // 1 second **** CUSTOM TESTING SETTINGS ****
    max: 1000 // limit each IP to 1000 requests per windowMs
  });

function createServer() {
    const app = express(); 

    app.use(passport.initialize()); // initializes passport obj on every request
    app.use(express.json({ limit: '10kb' })); // reads requests as json, helps against DOS attacks
    app.use(helmet()); // protects against minor attacks
    app.use(limiter); // protects against brute force attacks
    app.use('/api', router); // needs to go after all middleware

    return app
}
module.exports = createServer;