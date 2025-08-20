// agents.js
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { connectToDB } = require('./db');
const crypto = require("crypto");
const bcrypt = require("bcrypt");


function generateAccessToken(length = 48) {
  return crypto.randomBytes(length).toString("hex");
}

async function hashToken(token) {
  const saltRounds = 12; // adjust cost factor as needed
  return await bcrypt.hash(token, saltRounds);
}

// Verify token against stored hash
async function verifyToken(token, hash) {
  return await bcrypt.compare(token, hash);
}

router.get('/register', async (req, res) => {

  console.log('Register received');

  //For the moment, no security

  // Generate a GUID
  const guid = uuidv4();

  //Generate random access token
  const token = generateAccessToken(32); // 32 bytes = 64 hex characters

  const hashedToken = await hashToken(token);

  let client;

  try {
    ({ client, db } = await connectToDB());

    const result = await db.collection('agents').insertOne({ guid, hashedToken });

    console.log('Agent registered');

  } catch (err) {
    console.error('Error updating agent information:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

  // Return it in a JSON object
  res.json({ guid, token });

});

// Heartbeat endpoint
router.post('/heartbeat', async (req, res) => {

  console.log('Heartbeat received:', req.body);

  // Destructure expected fields
  const { guid, computer_name, os_version, user, ip_addresses, agent_version } = req.body;
  const authHeader = req.headers['authorization'];
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!guid) {
    return res.status(400).json({ error: 'Missing guid' });
  }

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const providedToken = authHeader.split(' ')[1];

  let client, db;

  try {
    ({ client, db } = await connectToDB());

    // Find agent by guid
    const agent = await db.collection('agents').findOne({ guid });

    if (!agent) {
      return res.status(404).json({ error: 'Agent not found' });
    }

    // Check token hash
    if (!verifyToken(agent.hashedToken, providedToken)) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Update agent info
    await db.collection('agents').updateOne(
      { guid },
      {
        $set: {
          ip,
          lastHeartbeat: new Date(),
          computer_name,
          os_version,
          user,
          ip_addresses,
          agent_version
        }
      }
    );

    return res.json({
      status: 'ok',
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error('Error updating agent information:', err);
    return res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

module.exports = router;