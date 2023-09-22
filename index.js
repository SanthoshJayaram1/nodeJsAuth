const express = require('express');
require('dotenv').config();
const {PORT} = process.env;
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');
const connectWithDb = require('./config/key');

const app = express();

// Passport Configuration
require('./config/passport');

// DB Configuration
connectWithDb();

// EJS Configuration
app.use(expressLayouts);
app.use("/assets", express.static('./assets'));
app.set('view engine', 'ejs');

// Bodyparser Configuration
app.use(express.urlencoded({ extended: false }))

// Express session Configuration
app.use(
    session({
        secret: 'secret',
        resave: true,
        saveUninitialized: true,
        maxAge: 30 * 60 * 1000
    })
);

// Passport Middlewares
app.use(passport.initialize());
app.use(passport.session());
require('./config/passport-google-oauth2-strategy');


// Connecting flash
app.use(flash());

// Global variables
app.use(function(req, res, next) {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});
// Routes
app.use('/', require('./routes/index'));
app.use('/auth', require('./routes/auth'));


// server
app.listen(PORT || 5000, function(err){
    if (err){
        console.log(`Error in running the server: ${err}`);
    }

    console.log(`Server is running on port: ${PORT}`);
});
