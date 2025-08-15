// agents.js
const express = require('express');
const router = express.Router();

// Heartbeat endpoint
router.get('/heartbeat', (req, res) => {
  console.log('Heartbeat received:', req.body);

  res.json({
    status: 'ok',
    timestamp: new Date().toISOString()
  });
});

module.exports = router;