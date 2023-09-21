const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const passport=require('passport');
const { ensureAuthenticated } = require('../config/checkAuth');

// user login routes
router.get('/login',authController.loginHandlePage );     //---->1. this renders login page 
// after login is succussfull it redirects to dashboard 
router.post('/login', passport.authenticate('local', {
    failureRedirect: '/auth/login',
    failureFlash: true
}),(req,res)=>res.redirect('/dashboard'));//-------------------->2. this creates session and redirects to dashboard


// registration and user activation routes
router.get('/register', (req, res) => res.render('register1'));//---->1. this renders register page
router.post('/register', authController.registerHandle);     //------>2. this submits the user credentials and generate token and sent that in link through mail
router.get('/activate/:token', authController.activateHandle);//----->3. this verify the user and create credentials in database

// user forgot password
router.get('/forgot', (req, res) => res.render('forgot1'));  //------>1. we got to forgot password page and enter email
router.post('/forgot', authController.forgotPassword);      //------->2. we submit the email, then one token is generated and link one link sent through mail
router.get('/forgot/:token', authController.gotoReset);    //-------->3. we click on this link then it verify the token and redirect to reset password page
router.get('/reset/:id',authController.handleForgetPassword);//------>4. here we verify params id and then changes password in database

//user reset routes
router.get('/reset/',ensureAuthenticated,(req,res)=>res.render('reset1'));//-->1. this is reset password option after logging in
router.post('/reset/', authController.resetPassword);//----------------------->2. this resets the password in the database

// user logout routes
router.get('/logout', authController.logoutHandle);

module.exports = router;