const passport = require('passport');
const googleStrategy = require('passport-google-oauth').OAuth2Strategy;
const crypto = require('crypto');
const User=require('../models/User');


// tell passport to use a new strategy for google login
passport.use(new googleStrategy({
        clientID: "297963479359-jjmk1m3vk5ic3gr0kje2vmd72bg36sbh.apps.googleusercontent.com",
        clientSecret: "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",
        callbackURL: "http://nodejsoauth.onrender.com/auth/google/callback"
    },
    function(accessToken, refreshToken, profile, done){
        // find a user
        User.findOne({email: profile.emails[0].value}).exec(function(err, user){
            if (err){console.log('error in google strategy-passport', err); return;}
            console.log(accessToken, refreshToken);
            console.log(profile);

            if (user){
                // if found, set this user as req.user
                return done(null, user);
            }else{
                // if not found, create the user and set it as req.user
                User.create({
                    name: profile.displayName,
                    email: profile.emails[0].value,
                    password: crypto.randomBytes(20).toString('hex')
                }, function(err, user){
                    if (err){console.log('error in creating user google strategy-passport', err); return;}

                    return done(null, user);
                });
            }

        }); 
    }


));


module.exports = passport;
