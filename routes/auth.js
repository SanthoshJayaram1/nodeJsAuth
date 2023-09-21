const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');


// user login routes
router.get('/login', (req, res) => res.render('login1'));
router.post('/login', authController.loginHandle);

// register routes
router.get('/register', (req, res) => res.render('register1'));
router.post('/register', authController.registerHandle);

// user activation route
router.get('/activate/:token', authController.activateHandle);

// user forgot password
router.post('/forgot', authController.forgotPassword);
router.get('/forgot', (req, res) => res.render('forgot1'));
router.get('/forgot/:token', authController.gotoReset);

//user reset routes
router.get('/reset/:id', (req, res) => {res.render('reset1', { id: req.params.id });});
router.post('/reset/:id', authController.resetPassword);

// user logout routes
router.get('/logout', authController.logoutHandle);

module.exports = router;