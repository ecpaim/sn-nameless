const express = require('express');
const app = express(); 
const passport = require('passport');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");
const cors = require('cors');
const axios = require('axios');
const {nanoid} = require('nanoid');

var BusBoy = require('busboy'); // all that to read incoming files
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs');


const router = express.Router(); // to add /api prefix

const utils = require('./util/hash-and-token');
const {validateSignupData, validateLoginData, validateText} = require('./util/validation');

require('./config/passport')(passport);
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  });
  
app.use(cors());
app.use(passport.initialize()); // initializes passport obj on every request
app.use(express.json({ limit: '20kb' })); // reads requests as json, helps against DOS attacks
app.use(express.json()); // reads requests as json, helps against DOS attacks
app.use(helmet()); // protects against minor attacks
app.use(limiter); // protects against brute force attacks
app.use('/api', router); // needs to go after all middleware


// AWS and DynamoDB
var AWS = require("aws-sdk");
AWS.config.update({
    region: "sa-east-1",
    endpoint: "https://dynamodb.sa-east-1.amazonaws.com"
});
var docClient = new AWS.DynamoDB.DocumentClient()

// backblaze b2
const { B2KEY, KEYID, BUCKETID } = require('../../.backblaze/credentials');
let encodedBase64 = Buffer.from(KEYID +':'+ B2KEY).toString('base64');
let credentials;
axios.post(
    `https://api.backblazeb2.com/b2api/v1/b2_authorize_account`,
    {},
    {
        headers: { Authorization: 'Basic ' + encodedBase64 }
    })
.then(function (response) {
        var data = response.data
        credentials = {
            accountId: KEYID,
            applicationKey: B2KEY,
            apiUrl: data.apiUrl,
            authorizationToken: data.authorizationToken,
            downloadUrl: data.downloadUrl,
            recommendedPartSize: data.recommendedPartSize
        }
        console.log(credentials);
    })
    .catch(function (err) {
       return console.log(err); 
});


// MAIN PAGE
router.get('/', (req,res) =>{
    return res.status(200).json({success: true, msg: 'hello world'});
});

// LOGIN PAGE
router.post('/login', (req,res) => {

    // just checks if fields are not empty or badly written
    const {errors, valid, email} = validateLoginData(req.body);
    if(!valid){
        return res.status(400).json({errors: errors, success: false});
    }
  
    if(email){

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

// PROTECTED ROUTE, FOR TESTING PURPOSES
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
    creates a post WITHOUT IMAGES with fields:
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
        feed: req.body.feed,
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

// uploads image with timestamp and description to backblaze and dynamodb
// post in db looks like this:
// let newPost = {
//     PKEY: req.user.PKEY,
//     SKEY: 'POST#' + req.user.PKEY.substring(5) + '#' + timestamp,
//     timestamp: timestamp,
//     description: description,
//     imgUrl: credentials.downloadUrl + '/file/SNpics/' + response.data.fileName,
//     imgId: response.data.fileId,
//     nComments: 0,
//     nLikes: 0,
//     nGifts: 0,
//     lastComment: {}
// }
router.post('/pstimg', passport.authenticate('jwt', {session:false}), (req,res) => {


    var busboy = new BusBoy({ headers: req.headers});

    // console.log(req.headers['content-type']);
    // req.on('data', function(d) { console.dir(''+d); });
    
    let imageFileName;
    let imageToBeUploaded = {};
    let numberOfImages = 1; // overkill, will be useful if we upload more than one img
    let description;
    let readDescription = false;
    let timestamp;
    let readTimestamp = false;
    let feed;
    let readFeed = false;

    //   busboy parses incoming HTML form data
    busboy.on('field', (fieldName, value) => { // reads post description
        if(fieldName === 'description'){
            console.log("READ DESCRIPTION: ");
            console.log(value);
            description = validateText(value);
            readDescription = true;
        }else if(fieldName === 'timestamp'){
            console.log("READ TIMESTAMP: ");
            console.log(value);
            timestamp = validateText(value);
            readTimestamp = true;
        } if(fieldName === 'feed'){
            console.log("READ FEED: ");
            console.log(value);
            feed = validateText(value);
            readFeed= true;
        } else {
            console.log("DIFFERENT FIELD IDK");
            console.log(fieldName);
        }
    });


    //console.log(postData); //wont work, busboy.on is async

    busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
        console.log("ENTERED ON.FILE");
        if(mimetype !== 'image/jpeg' && mimetype !== 'image/png' && mimetype !== 'image/jpg') {
            return res.status(400).json({ error: 'Wrong file type submitted' });
        }

        // console.log('fieldname: '+ fieldname);
        // console.log('filename: '+ filename);
        // console.log('mimetype: '+ mimetype);

        //get extension of image type
        const imageExtension = filename.split('.')[filename.split('.').length -1];
        //example 345658476847684678.png
        imageFileName = `public-${nanoid()}.${imageExtension}`;

        const filepath = path.join(os.tmpdir(), imageFileName);
        console.log(filepath);
        imageToBeUploaded = { filepath, mimetype };

        //creates the file
        let fstream = fs.createWriteStream(filepath)
        file.pipe(fstream);

        fstream.on('finish', () => {
            numberOfImages = numberOfImages - 1;
            if( numberOfImages === 0){
                try {
                    var stats = fs.statSync(imageToBeUploaded.filepath);
                  }
                  catch(err) {
                    return res.status(500).json({success: false, msg: "Server could not receive file."});
                  }
              
                console.log('File Size in Bytes: ' + stats.size);
                console.log('path: ' + imageToBeUploaded.filepath);

             
                    axios.post( credentials.apiUrl + '/b2api/v1/b2_get_upload_url', {bucketId: BUCKETID }, { headers: { Authorization: credentials.authorizationToken } })
                        .then( (response) => {
                            console.log(response.data.uploadUrl);
                            var uploadUrl = response.data.uploadUrl;
                            var uploadAuthorizationToken = response.data.authorizationToken;
                            var source = fs.readFileSync(filepath);
                    
                            var sha1 = crypto.createHash('sha1').update(source).digest("hex");
                        
                            axios.post( uploadUrl, source,
                                        {headers: {
                                            Authorization: uploadAuthorizationToken,
                                            "X-Bz-File-Name": imageFileName,
                                            "Content-Type": "b2/x-auto",
                                            "Content-Length": stats.size + 40, // size of file + "When sending the SHA1 checksum at the end, the Content-Length should be set to the size of the file plus the 40 bytes of hex checksum."
                                            "X-Bz-Content-Sha1": sha1,
                                            "X-Bz-Info-Author": "unknown"
                                        }}
                            ).then( (response) => {
                               

                                console.log(response.data);
                                
                                while(readDescription === false || readTimestamp === false || readFeed === false){
                                    continue;
                                }
                                let newPost = {
                                    PKEY: req.user.PKEY,
                                    SKEY: 'POST#' + req.user.PKEY.substring(5) + '#' + timestamp,
                                    feed: feed,
                                    timestamp: timestamp,
                                    description: description,
                                    imgUrl: credentials.downloadUrl + '/file/SNpics/' + response.data.fileName,
                                    imgId: response.data.fileId,
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
                                        // will have to delete the picture...
                                        res.status(500).json({success: false, msg: 'Could not add post to db'});
                                    } else {
                                        res.status(200).json({
                                            success: true, 
                                            msg: 'Post created successfully', 
                                            post: {
                                                timestamp: newPost.timestamp,
                                                description: newPost.description,
                                                imgUrl: newPost.imgUrl,
                                                nComments: 0,
                                                nLikes: 0,
                                                nGifts: 0,
                                                lastComment: {}
                                            }});
                                    }
                                });

                            }).catch((err) => {
                                // this is a little messy. Basically we copy the code again because b2 may fail on the first try.
                                axios.post( credentials.apiUrl + '/b2api/v1/b2_get_upload_url', {bucketId: BUCKETID }, { headers: { Authorization: credentials.authorizationToken } })
                                .then( (response) => {
                
                                    var uploadUrl = response.data.uploadUrl;
                                    var uploadAuthorizationToken = response.data.authorizationToken;
                                    var source = fs.readFileSync(filepath);
                                    var sha1 = crypto.createHash('sha1').update(source).digest("hex");
                                
                                    axios.post( uploadUrl, source,
                                                {headers: {
                                                    Authorization: uploadAuthorizationToken,
                                                    "X-Bz-File-Name": imageFileName,
                                                    "Content-Type": "b2/x-auto",
                                                    "Content-Length": stats.size + 40, // size of file + "When sending the SHA1 checksum at the end, the Content-Length should be set to the size of the file plus the 40 bytes of hex checksum."
                                                    "X-Bz-Content-Sha1": sha1,
                                                    "X-Bz-Info-Author": "unknown"
                                                }}
                                    ).then( (response) => {

                                        while(readDescription === false || readTimestamp === false){
                                            continue;
                                        }
                                        let newPost = {
                                            PKEY: req.user.PKEY,
                                            SKEY: 'POST#' + req.user.PKEY.substring(5) + '#' + timestamp,
                                            feed: feed,
                                            timestamp: timestamp,
                                            description: description,
                                            imgUrl: credentials.downloadUrl + '/file/SNpics/' + response.data.fileName,
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
                                                // will have to delete the picture...
                                                res.status(500).json({success: false, msg: 'Could not add post to db'});
                                            } else {
                                                res.status(200).json({
                                                    success: true, 
                                                    msg: 'Post created successfully', 
                                                    post: {
                                                        timestamp: newPost.timestamp,
                                                        description: newPost.description,
                                                        imgUrl: newPost.imgUrl,
                                                        nComments: 0,
                                                        nLikes: 0,
                                                        nGifts: 0,
                                                        lastComment: {}
                                                    }});
                                            }
                                        });

                                    }).catch((err) => {
                                        res.status(500).json({success: false, msg: "Error uploading file to bucket."});
                                    });
                                })
                                .catch(function (err) {
                                    res.status(500).json({success: false, msg: "Error getting upload url."});
                                });
                            });
                        })
                        .catch(function (err) {
                            // as far as I can tell from B2 docs, the chance of b2_get_upload_url failing is pretty low. so no need to try again
                            res.status(500).json({success: false, msg: "Error getting upload url."});
                        });
                
            }
        });
    });

    // "However if you're writing a file stream to disk, it's possible for the file stream
    //  to still have the last chunk(s) of data still buffered in memory" 
    //busboy.on('finish', () => {    });

    return req.pipe(busboy); //close the request, use Rawbody with cloud functions
});

// gets all posts in the database
router.get('/mainfeed',  (req,res) =>{
    
    var params = {
        TableName: "SNROOT",
        IndexName: "feed-index",
        KeyConditionExpression: "feed = :arg1",
        ExpressionAttributeValues:{
            ":arg1": 'MAIN'
        }
    };

    docClient.query(params, function(err,data) {
        if(err){
            console.log(err);
            return res.status(500).json({success: false, msg: 'Could not retrieve posts'});
        } else {
            let posts = [];
            data.Items.forEach( function(item) {
                if(item.imgUrl){
                    posts.push({
                        id: item.SKEY,
                        username: item.PKEY.substring(5),
                        timestamp: item.timestamp,
                        description: item.description,
                        imgUrl: item.imgUrl,
                        nComments: item.nComments,
                        nLikes: item.nLikes,
                        nGifts: item.nGifts,
                        lastComment: item.lastComment
                    });
                } else {
                    posts.push({
                        id: item.SKEY,
                        username: item.PKEY.substring(5),
                        timestamp: item.timestamp,
                        description: item.description,
                        nComments: item.nComments,
                        nLikes: item.nLikes,
                        nGifts: item.nGifts,
                        lastComment: item.lastComment
                    });
                }
            });
            return res.json(posts);

        }
    });
});

// removes post from dynamo then removes image from blackbaze
// the only parameter is timestamp of the post
// gets post info from the db, then deletes from db,b2
// currently there is a chance that it is removed from b2 and not from dynamo
router.post('/dltpst', passport.authenticate('jwt', {session:false}), (req,res) => {

    var params = {
        TableName : "SNROOT",
        Key: {
            PKEY: req.user.PKEY,
            SKEY: 'POST#' + req.user.PKEY.substring(5) + '#' + req.body.timestamp // potentially unsafe? maybe needs to escape timestamp
        }
      };
      docClient.get(params, function(err, data) {
        if(err){
            console.log("Unexpected error ocurred while trying to get post from db: ", JSON.stringify(err, null, 2));
            
            return res.status(500).json({success: false, msg: 'Could not delete post. Please try again!'});

        } else if (!data.Item) {

            return res.status(500).json({success: false, msg: 'Could not delete post. Please try again!'});
      
        }else {

            let imgName = data.Item.imgUrl.split('/');
            
           
            imgName = imgName[imgName.length - 1];
            console.log(imgName);

            let imgId = data.Item.imgId;
            console.log(imgId);

            axios.post( credentials.apiUrl + '/b2api/v1/b2_delete_file_version', {fileName: imgName, fileId: imgId }, { headers: { Authorization: credentials.authorizationToken } })
                .then( (response) => {

                    console.log('\n image removed successfully from b2!\n');
                    console.log(response);

                    var params = {
                        TableName: 'SNROOT',
                        Key: {
                            PKEY: req.user.PKEY,
                            SKEY: 'POST#' + req.user.PKEY.substring(5) + '#' + req.body.timestamp,
                        }
                    }
                    docClient.delete(params, function(err, data){
                        if(err){
                            console.log(err);
                            return res.status(500).json({success: false, msg: 'Could not delete post. Please try again!'});
                        }else{
                            return res.status(200).json({success: true, msg: 'Post removed successfully!'});
                        }
                    });

                })
                .catch(function (err) {
                    
                   return res.status(500).json({success: false, msg: 'Could not delete post. Please try again!'});
                });


            
        }

    });


});


module.exports.router = router;

port = 3001
app.listen(port, () => {
    console.log(`Listening on localhost:${port}/api`)
})
