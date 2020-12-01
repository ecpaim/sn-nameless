var AWS = require("aws-sdk");
var fs = require('fs');

AWS.config.update({
  region: "sa-east-1",
  endpoint: "https://dynamodb.sa-east-1.amazonaws.com"
});



var docClient = new AWS.DynamoDB.DocumentClient();
/*
var params = {
    TableName: "SNROOT",
    KeyConditionExpression: "PKEY = :pk AND SKEY BETWEEN :metadata AND :metadata2",
    ExpressionAttributeValues: {
        ":pk": "USER#jonas01",
        ":metadata": "#METADATA#",
        ":metadata2": "POST$" 
    },
    ScanIndexForward: true
};

docClient.query(params, function(err, data) {
    if (err) {
        console.error("Unable to query item. Error JSON:", JSON.stringify(err, null, 2));
    } else {
        console.log("Query succeeded:", JSON.stringify(data, null, 2));
    }
});
*/

var params = {
    TableName: "SNROOT",
    IndexName: "EmailIndex",
    KeyConditionExpression: "email = :em",
    ExpressionAttributeValues:{
        ":em": "ana2@email.com"
    }
};

// The GetItem and GetBatchItem operations can't be used on a global secondary index. 
docClient.query(params, function(err, data) {
    if(err){
        console.log("Unexpected error ocurred while trying to get email from db: ", JSON.stringify(err, null, 2));
        
    } else if(data.Items.length > 0){
        console.log("Query successful but email already in use: ", JSON.stringify(data, null, 2));
    } else {
        console.log("get was successfull and email is available:", JSON.stringify(data, null, 2));
    }
});