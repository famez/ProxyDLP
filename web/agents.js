// agents.js
const express = require('express');
const router = express.Router();
const { connectToDB } = require('./db');


// Heartbeat endpoint
router.get('/heartbeat', async (req, res) => {
  console.log('Heartbeat received:', req.body);

  // Get client IP
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  let client;

  try {
    ({ client, db } = await connectToDB());

    await db.collection('agents').updateOne(
      { ip }, // find by ip
      {
        $set: {
          ip,
          lastHeartbeat: new Date(),
          status: "online" // store extra info if needed
        }
      },
      { upsert: true }
    );

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error('Error updating agent information:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

});

module.exports = router;