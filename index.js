const express = require('express');
const app = express(); 
const passport = require('passport');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");
const router = express.Router(); // to add /api prefix

const utils = require('./util/hash-and-token');
const {validateSignupData, validateLoginData} = require('./util/validation');

require('./config/passport')(passport);
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  });

app.use(passport.initialize()); // initializes passport obj on every request
app.use(express.json({ limit: '10kb' })); // reads requests as json, helps against DOS attacks
app.use(helmet()); // protects against minor attacks
app.use(limiter); // protects against brute force attacks
app.use('/api', router); // needs to go after all middleware

// just for tests
const { users } = require('./db');
console.log(users);

// MAIN PAGE
router.get('/', (req,res) =>{
    res.send('hello world')
});

// LOGIN PAGE
router.post('/login', (req,res) => {

    // just checks if fields are not empty or bad written
    const {errors, valid, email} = validateLoginData(req.body);
    if(!valid){
        return res.status(400).json({errors: errors, success: false});
    }
    let userExists;
    if(email){
        // will be replaced by a db call
        userExists = users.filter(user => user.email === req.body.emailOrUser);
    }
    else{
        // will be replaced by a db call
        userExists = users.filter(user => user.username === req.body.emailOrUser);
    }
    
  
    if (userExists.length === 0) {
        return res.status(401).json({ errors: { emailOrUser: 'Couldnt find email or username'}, success: false});
    } else {

        let user = userExists[0];
        const isValid = utils.validPassword(req.body.password, user.hash, user.salt);

        if(isValid){
            const token = utils.issueJWT(user);
            
           return res.status(200).json({token: token, success: true});
        } else {
           return res.status(401).json({ errors: { password: 'Invalid password'}, success: false });
        }
    }

});

// SIGNUP PAGE
router.post('/signup', (req,res) => {

    const {errors, valid} = validateSignupData(req.body);

    if(valid){
        const {salt, hash} = utils.genPassword(req.body.password);
        const newUser = {
            _id: req.body.username,
            username: req.body.username,
            email: req.body.email,
            hash: hash,
            salt: salt
        };
        // this will be replaced by a db call
        users.push(newUser);
        if(true){
            const token = utils.issueJWT(newUser)
            console.log(newUser)
            
            return res.status(200).json({token: token, success: true});
        } else {
            return res.status(500).json({msg: 'couldnt add user to database', success: true});
        }
    } else {
        return res.status(400).json({errors: errors, success: false});
    }
});

// PROTECTED ROUTE, FOR TESTING PORPOUSES
// we need {session: false} because jwt doesnt use sessions
router.get('/protected', passport.authenticate('jwt', {session:false}), (req,res) =>{
    
    res.status(200).json({success: true, msg: 'you entered the protected route'})
});

port = 3000
app.listen(port, () => {
    console.log(`Listening on localhost:${port}/api`)
})
