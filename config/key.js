const mongoose = require('mongoose');

const url="mongodb+srv://user2003:user2003@cluster0.atkywud.mongodb.net/?retryWrites=true&w=majority";
const connectWithDb = () => {
    try{
        mongoose.connect(url,{useUnifiedTopology:true,useNewUrlParser:true});
        console.log("Database connected successfully");
    }catch(err){
        console.log("Error while comnnecting to the database",err);
    }
};

module.exports = connectWithDb;