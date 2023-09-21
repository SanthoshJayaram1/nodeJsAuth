const express = require('express');
const router = express.Router();
const { ensureAuthenticated } = require('../config/checkAuth')

// welcome route
router.get('/', (req, res) => {
    res.render('welcome');
});

// Dashboard Route 
router.get('/dashboard', ensureAuthenticated, (req, res) => res.render('dashboard', {
    name: req.user.name
}));

module.exports = router;