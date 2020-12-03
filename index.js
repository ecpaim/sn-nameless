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
app.use(express.json({ limit: '20kb' })); // reads requests as json, helps against DOS attacks
app.use(helmet()); // protects against minor attacks
app.use(limiter); // protects against brute force attacks
app.use('/api', router); // needs to go after all middleware

// just for tests
const { users } = require('./db');
//console.log(users);

// AWS and DynamoDB
var AWS = require("aws-sdk");
AWS.config.update({
    region: "sa-east-1",
    endpoint: "https://dynamodb.sa-east-1.amazonaws.com"
});
var docClient = new AWS.DynamoDB.DocumentClient()

// MAIN PAGE
router.get('/', (req,res) =>{
    res.status(200).json({success: true, msg: 'hello world'});
});

// LOGIN PAGE
router.post('/login', (req,res) => {

    // just checks if fields are not empty or bad written
    const {errors, valid, email} = validateLoginData(req.body);
    if(!valid){
        return res.status(400).json({errors: errors, success: false});
    }
  
    if(email){
        // will be replaced by a db call

        var params = {
            TableName: "SNROOT",
            IndexName: "EmailIndex",
            KeyConditionExpression: "email = :em",
            ExpressionAttributeValues:{
                ":em": req.body.emailOrUser.trim()
            }
        };

        docClient.query(params, function(err, data) {
            if(err){
                console.log("Unexpected error ocurred while trying to get email from db: ", JSON.stringify(err, null, 2));

                return res.status(500).json({errors: { emailOrUser: 'Couldnt find email or username'}, success: false});

            } else if (data.Items.length == 0) {

                return res.status(401).json({ errors: { emailOrUser: 'Couldnt find email or username'}, success: false});
          
            }else {

                let user = data.Items[0];

                const isValid = utils.validPassword(req.body.password, user.hash, user.salt);

                if(isValid){

                    const token = utils.issueJWT(user);  
                    return res.status(200).json({token: token, success: true});

                } else {
                    return res.status(401).json({ errors: { password: 'Invalid password'}, success: false });
                }
            }

        });

    }
    else{
        // will be replaced by a db call
        var params = {
            TableName : "SNROOT",
            Key: {
                PKEY: 'USER#' + req.body.emailOrUser.trim(),
                SKEY: '#METADATA#' + req.body.emailOrUser.trim() 
            }
          };
          docClient.get(params, function(err, data) {
            if(err){
                console.log("Unexpected error ocurred while trying to get user from db: ", JSON.stringify(err, null, 2));
                
                return res.status(500).json({errors: { emailOrUser: 'Couldnt find email or username'}, success: false});

            } else if (!data.Item) {

                return res.status(401).json({ errors: { emailOrUser: 'Couldnt find email or username'}, success: false});
          
            }else {

                let user = data.Item;

                const isValid = utils.validPassword(req.body.password, user.hash, user.salt);

                if(isValid){

                    const token = utils.issueJWT(user);  
                    return res.status(200).json({token: token, success: true});

                } else {
                    return res.status(401).json({ errors: { password: 'Invalid password'}, success: false });
                }
            }

        });
    }
    

});

// SIGNUP PAGE
router.post('/signup', (req,res) => {

    const {errors, valid} = validateSignupData(req.body);

    //A global secondary index only tracks data items where its key attributes actually exist
    if(valid){ // checks if email is not being used by another account
        var params = {
            TableName: "SNROOT",
            IndexName: "EmailIndex",
            KeyConditionExpression: "email = :em",
            ExpressionAttributeValues:{
                ":em": req.body.email.trim()
            }
        };
        docClient.query(params, function(err, data) {
            if(err){
                console.log("Unexpected error ocurred while trying to get email from db: ", JSON.stringify(err, null, 2));
                errors.email = "Couldn't verify email.";
                return res.status(500).json({errors, success: false});

            } else if (data.Items.length > 0) {
                //console.error("Email already being used. Error JSON:", JSON.stringify(err, null, 2));
                errors.email = "Email already being used.";
                return res.status(400).json({errors, success: false});

            }else {
                
                // add new user to db and send back jwt 
                const {salt, hash} = utils.genPassword(req.body.password);
                const newUser = {
                    PKEY: 'USER#' + req.body.username.trim(),
                    SKEY: '#METADATA#' + req.body.username.trim(),
                    email: req.body.email.trim(),
                    hash: hash,
                    salt: salt
                };

                var params = {
                    TableName: "SNROOT",
                    Item: newUser,
                    ConditionExpression: "attribute_not_exists(SKEY)"
                };
                
                docClient.put(params, function(err, data) {
                    if (err) {
                        //console.error("Unable to add user to the database. Error JSON:", JSON.stringify(err, null, 2));
                        errors.username = "Username already being used.";
                        return res.status(400).json({errors, success: false});

                    } else {
                        //console.log("User successfully added to the database:", JSON.stringify(data, null, 2));

                        const token = utils.issueJWT(newUser)
                        
                        return res.status(200).json({token: token, success: true});
                    }
                });
            }
        });
    } else {
        // invalid field contents
        return res.status(400).json({errors: errors, success: false});
    }
    
});

// PROTECTED ROUTE, FOR TESTING PORPOUSES
// we need {session: false} because jwt doesnt use sessions
router.get('/protected', passport.authenticate('jwt', {session:false}), (req,res) =>{
    
    res.status(200).json({success: true, msg: 'you entered the protected route'})
});

// delete account (DOES NOT DELETE POSTS, WILL REQUIRE REFACTOR LATER)
router.post('/exc', passport.authenticate('jwt', {session:false}), (req,res) =>{

    //verifies if password in req.body matches JWT token
    const isValid = utils.validPassword(req.body.password, req.user.hash, req.user.salt);

    if(isValid){
        //removes user from db

        var params = {
            TableName: 'SNROOT',
            Key: {
                PKEY: req.user.PKEY,
                SKEY: req.user.SKEY
            }
        }
        docClient.delete(params, function(err, data){
            if(err){
                return res.status(500).json({success: false, msg: 'Could not remove user from database'});
            }else{
                return res.status(200).json({success: true, msg: 'User removed successfully'});
            }
        })


    } else {
        return res.status(400).json({success: false, msg: 'Invalid password'});
    }

    
});

/* 
    creates a post with fields:
        timestamp: time post was sent
        description: the text
        numberComments:
        numberLikes:
        numberGifts:
        last comment: another json
        picture: to do
*/
router.post('/pst', passport.authenticate('jwt', {session:false}), (req,res) =>{
    const newPost = {
        PKEY: req.user.PKEY,
        SKEY: 'POST#' + req.user.PKEY.substring(5) + '#' + req.body.timestamp,
        timestamp: req.body.timestamp,
        description: req.body.description,
        nComments: 0,
        nLikes: 0,
        nGifts: 0,
        lastComment: {}
    };

    var params = {
        TableName: "SNROOT",
        Item: newPost,
        ConditionExpression: "attribute_not_exists(SKEY)"
    };
    
    docClient.put(params, function(err, data) {
        if(err){
            return res.status(500).json({success: false, msg: 'Could not create post'});
        } else {
            return res.status(200).json({success: true, msg: 'Post created successfully'});
        }
    });
});

// deletes post. body contains timestamp: timestamp of post
// this will have to be refactored to remove likes, comments and gifts as well
router.post('/excpst', passport.authenticate('jwt', {session:false}), (req,res) =>{

    var params = {
        TableName: 'SNROOT',
        Key: {
            PKEY: req.user.PKEY,
            SKEY: 'POST#' + req.user.PKEY.substring(5) + '#' + req.body.timestamp
        }
    }
    docClient.delete(params, function(err, data){
        if(err){
            return res.status(500).json({success: false, msg: 'Could not remove post from database'});
        }else{
            return res.status(200).json({success: true, msg: 'Post removed successfully'});
        }
    })
});

module.exports.router = router;

port = 3000
app.listen(port, () => {
    console.log(`Listening on localhost:${port}/api`)
})
