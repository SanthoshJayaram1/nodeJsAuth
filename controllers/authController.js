const passport = require('passport');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require('jsonwebtoken');
// const JWT_KEY = "jwtactive987";
// const JWT_RESET_KEY = "jwtreset987";
const {CLIENT_ID,CLIENT_SECRET,REFRESH_TOKEN,JWT_KEY,JWT_RESET_KEY,USER_EMAIL,REDIRECT_URL}=process.env;

// User Model 
const User = require('../models/User.js');

//<----------------------------------------------------------- Login controllers---------------------------------------------->//

// login handle
exports.loginHandlePage=async(req,res)=>{
    if(req.user){
     res.redirect('/dashboard');
    }else{
     res.render('login1');
    }
 }

//<---------------------------------------------- registration and user activation controllers----------------------------->//

 // registerhandle
 exports.registerHandle = (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // Checking required fields 
    if (!name || !email || !password || !password2) {
        console.log(req.body);
        errors.push({ msg: 'Please enter all fields' });
    }

    // Checking password mismatch 
    if (password != password2) {
        errors.push({ msg: 'Passwords do not match' });
    }

    // Checking password length 
    if (password.length < 8) {
        errors.push({ msg: 'Password must be at least 8 characters' });
    }

    if (errors.length > 0) {
        res.render('register1', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // Validation passed 
        User.findOne({ email: email }).then(user => {
            if (user) {
                // if User already exists 
                errors.push({ msg: 'Email ID already registered' });
                res.render('register1', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else {
                // if user does'nt exist in database

                // create Oauth2 client object with clientID and clientSecret
                const oauth2Client = new OAuth2(
                    CLIENT_ID, // ClientID
                    CLIENT_SECRET, // Client Secret
                    REDIRECT_URL // Redirect URL
                );
                // set refresh token to the credentials
                oauth2Client.setCredentials({
                    refresh_token: REFRESH_TOKEN,
                });
                // generate the access token 
                const accessToken = oauth2Client.getAccessToken();
                
                const token = jwt.sign({ name, email, password }, JWT_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;

                const output = `
                <h2>Please click on below link to activate your account</h2>
                <p>${CLIENT_URL}/auth/activate/${token}</p>
                <p><b>NOTE: </b> The above activation link expires in 30 minutes.</p>
                `;

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        type: "OAuth2",
                        user: USER_EMAIL,
                        clientId: CLIENT_ID,
                        clientSecret: CLIENT_SECRET,
                        refreshToken: REFRESH_TOKEN,
                        accessToken: accessToken
                    },
                });

                // send mail with defined transport object
                const mailOptions = {
                    from: `"Auth Admin" ${USER_EMAIL}`, // sender address
                    to: email, // list of receivers
                    subject: "Account Verification: NodeJS Auth ✔", // Subject line
                    generateTextFromHTML: true,
                    html: output, // html body
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error);
                        req.flash(
                            'error_msg',
                            'Something went wrong on our end. Please register again.'
                        );
                        res.redirect('/auth/login');
                    }
                    else {
                        console.log('Mail sent : %s', info.response);
                        req.flash(
                            'success_msg',
                            'Activation link sent to email ID. Please activate to log in.'
                        );
                        res.redirect('/auth/login');
                    }
                })

            }
        });
    }
}
// Activate Account Handle 
exports.activateHandle = (req, res) => {
    const token = req.params.token;
    let errors = [];
    if (token) {
        // here we decode the token we sent before through mail
        jwt.verify(token, JWT_KEY, (err, decodedToken) => {
            if (err) {
                req.flash(
                    'error_msg',
                    'Incorrect or expired link! Please register again.'
                );
                res.redirect('/auth/register');
            }
            else {
                // extract user details from the decoded token
                const { name, email, password } = decodedToken;
                // then checks in database whether user already exists or not
                User.findOne({ email: email }).then(user => {
                    if (user) {
                        // if User already exists 
                        req.flash(
                            'error_msg',
                            'Email ID already registered! Please log in.'
                        );
                        res.redirect('/auth/login');
                    } else {
                        // if doesnot exist, then creates new user
                        const newUser = new User({
                            name,
                            email,
                            password
                        });
                           // encrypt the password to hash and then save it to database
                        bcryptjs.genSalt(10, (err, salt) => {
                            bcryptjs.hash(newUser.password, salt, (err, hash) => {
                                if (err) throw err;
                                newUser.password = hash;
                                newUser
                                    .save()
                                    .then(user => {
                                        req.flash(
                                            'success_msg',
                                            'Account activated. You can now log in.'
                                        );
                                        res.redirect('/auth/login');
                                    })
                                    .catch(err => console.log(err));
                            });
                        });
                    }
                });
            }

        })
    }
    else {
        console.log("Account activation error!")
    }
}

//<---------------------------------------------------forgot password controllers-------------------------------------------->//

// Forgot Password Handle 
exports.forgotPassword = (req, res) => {
    const { email } = req.body;

    let errors = [];

    // Checking required fields 
    if (!email) {
        errors.push({ msg: 'Please enter an email ID' });
    }

    if (errors.length > 0) {
        res.render('forgot', {
            errors,
            email
        });
    } else {
        User.findOne({ email: email }).then(user => {
            if (!user) {
                // if User already exists 
                errors.push({ msg: 'User with Email ID does not exist!' });
                res.render('forgot', {
                    errors,
                    email
                });
            } else {

                const oauth2Client = new OAuth2(
                    CLIENT_ID, // ClientID
                    CLIENT_SECRET, // Client Secret
                    REDIRECT_URL // Redirect URL
                );

                oauth2Client.setCredentials({
                    refresh_token: REFRESH_TOKEN,
                });
                const accessToken = oauth2Client.getAccessToken()
                 // generates jwt token 
                const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;
                // this is HTML will be sent through mail
                const output = `
                <h2>Please click on below link to reset your account password</h2>
                <p>${CLIENT_URL}/auth/forgot/${token}</p>
                <p><b>NOTE: </b> The activation link expires in 30 minutes.</p>
                `;
                 // then after, that link will be update in user document with "resetLink" if it is present in database
                 // if not present then it will send mail 
                User.updateOne({ resetLink: token }, (err, success) => {
                    if (err) {
                        errors.push({ msg: 'Error resetting password!' });
                        res.render('forgot', {
                            errors,
                            email
                        });
                    }
                    else {
                        // nodemailer is used for sending mails
                        const transporter = nodemailer.createTransport({
                            service: 'gmail',
                            auth: {
                                type: "OAuth2",
                                user: USER_EMAIL,
                                clientId: CLIENT_ID,
                                clientSecret: CLIENT_SECRET,
                                refreshToken: REFRESH_TOKEN,
                                accessToken: accessToken
                            },
                        });
                        // send mail with defined transport object
                        const mailOptions = {
                            from: `"Auth Admin"${USER_EMAIL}`, // sender address
                            to: email, // list of receivers
                            subject: "Account Password Reset: NodeJS Auth ✔", // Subject line
                            html: output, // html body
                        };
                        // this sends the mail
                        transporter.sendMail(mailOptions, (error, info) => {
                            if (error) {
                                console.log(error);
                                req.flash(
                                    'error_msg',
                                    'Something went wrong on our end. Please try again later.'
                                );
                                // if there is error it again redirect to forgot password page
                                res.redirect('/auth/forgot');
                            }
                            else {
                                console.log('Mail sent : %s', info.response);
                                // after sending mail it redirects to login page
                                req.flash(
                                    'success_msg',
                                    'Password reset link sent to email ID. Please follow the instructions.'
                                );
                                res.redirect('/auth/login');
                            }
                        })
                    }
                })
            }
        });
    }
}

// Redirect to Reset Handle 
exports.gotoReset = (req, res) => {
    const { token } = req.params;
    if (token) {
        jwt.verify(token, JWT_RESET_KEY, (err, decodedToken) => {
            if (err) {
                req.flash(
                    'error_msg',
                    'Incorrect or expired link! Please try again.'
                );
                if(req.user){
                    res.redirect('/');
                }else{
                    res.redirect('/auth/login');
                }
            }
            else {
                const { _id } = decodedToken;
                User.findById(_id, (err, user) => {
                    if (err) {
                        req.flash(
                            'error_msg',
                            'User with email ID does not exist! Please try again.'
                        );
                        res.redirect('/auth/login');
                    }
                    else {
                        res.redirect(`/auth/reset/${_id}`)
                    }
                })
            }
        })
    }
    else {
        console.log("Password reset error!")
    }
}
// handleforgotpassword
exports.handleForgetPassword=async(req,res)=>{
    const id=req.params.id;
    try{
        const user=await User.findById(id);
        if(user){
            res.render("reset1");
         }
    }catch(error){
        res.redirect('/auth/login');
    }
}

// resetpassword Handle
exports.resetPassword = async(req, res) => {
    var { email,password, password2 } = req.body;
    let errors = [];
    const user=await User.findOne({email:email});
    const id=user.id;
    // Checking required fields 
    if (!password || !password2) {
        req.flash(
            'error_msg',
            'Please enter all fields.'
        );
        res.redirect(`/auth/reset/${id}`);
    }
    // Checking password length 
    else if (password.length < 8) {
        req.flash(
            'error_msg',
            'Password must be at least 8 characters.'
        );
        res.redirect(`/auth/reset/${id}`);
    }
    // Checking password mismatch 
    else if (password != password2) {
        req.flash(
            'error_msg',
            'Passwords do not match.'
        );
        res.redirect(`/auth/reset/${id}`);
    }
    else {
        bcryptjs.genSalt(10, (err, salt) => {
            // encrypt the password into hash and then save it to database
            bcryptjs.hash(password, salt, (err, hash) => {
                if (err) throw err;
                password = hash;
                User.findByIdAndUpdate(
                    { _id: id },
                    { password },
                    function (err, result) {
                        if (err) {
                            req.flash(
                                'error_msg',
                                'Error resetting password!'
                            );
                            res.redirect(`/auth/reset/${id}`);
                        } else {
                            req.flash(
                                'success_msg',
                                'Password reset successfully!'
                            );
                            res.redirect('/auth/login');
                        }
                    }
                );
            });
        });
    }
}

//<------------------------------------------------------------Logout controller---------------------------------------->//
exports.logoutHandle = (req, res) => {
    req.logout(function(err) {
        if (err) {
          console.log(err);
        }
        // Redirect or respond after logout
        req.flash('success_msg', 'You are logged out');
        res.redirect('/auth/login');
      });
    
}

//<----------------------------------------------------dashboard controllers-------------------------------------------->//
exports.dashboardPageHandle=async (req,res)=>{
        const user=await User.findOne({
            email: req.user.email
        });
        res.render('dashboard',{name:user.name,id:user.id});
}