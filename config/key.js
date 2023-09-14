const mongoose = require('mongoose');

const url = process.env.PS_DB_URI;

const connectWithDb = () => {
    try{
        mongoose.connect(url,{useUnifiedTopology:true,useNewUrlParser:true});
        console.log("Database connected successfully");
    }catch(err){
        console.log("Error while comnnecting to the database",err);
    }
};

module.exports = connectWithDb;