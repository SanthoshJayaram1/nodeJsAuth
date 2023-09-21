const express = require('express');
const router = express.Router();
const { ensureAuthenticated } = require('../config/checkAuth')
const authController = require('../controllers/authController');

// welcome route
router.get('/', (req, res) => {
    res.render('welcome');
});

// Dashboard Route 
router.get('/dashboard', ensureAuthenticated, authController.dashboardPageHandle);

module.exports = router;