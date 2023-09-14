module.exports = {
    MongoURI: "mongodb://admin:admin987@cluster0-shard-00-00.r3fs6.mongodb.net:27017,cluster0-shard-00-01.r3fs6.mongodb.net:27017,cluster0-shard-00-02.r3fs6.mongodb.net:27017/auth?authSource=admin&replicaSet=atlas-638q0p-shard-0&readPreference=primary&ssl=true"
}


const mongoose = require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/Nodejs-Auth');

const db = mongoose.connection;

db.on('error',console.error.bind(console,"Error connecting to MongoDB"));

db.once('open',function(){
    console.log("Connected to Database :: MongoDB");
});

module.exports = db;