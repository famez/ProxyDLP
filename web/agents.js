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


async function authenticateRequest(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw { status: 401, message: 'Missing or invalid Authorization header' };
  }

  const providedToken = authHeader.split(' ')[1];

  // guid depends on method
  let guid;
  if (req.method === 'GET') {
    guid = req.query.guid;
  } else if (req.method === 'POST') {
    guid = req.body.guid;
  }

  if (!guid) {
    throw { status: 400, message: 'Missing guid' };
  }

  let client, db;

  try {
    ({ client, db } = await connectToDB());

    const agent = await db.collection('agents').findOne({ guid });
    if (!agent) {
      throw { status: 404, message: 'Agent not found' };
    }

    const valid = await verifyToken(providedToken, agent.hashedToken);
    if (!valid) {
      throw { status: 401, message: 'Invalid token' };
    }

    return { agent, client, db };

  } catch (err) {
    if (client) await client.close();
    throw err;
  }
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
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  let client, db;

  try {

    const { agent, client: dbClient, db: database } = await authenticateRequest(req);
    client = dbClient;
    db = database;

    const { computer_name, os_version, user, ip_addresses, agent_version } = req.body;

    // Update agent info
    await db.collection('agents').updateOne(
      { guid: agent.guid },
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


router.get('/monitored_domains', async (req, res) => {

  let client, db;

  try {

    const { agent, client: dbClient, db: database } = await authenticateRequest(req);
    client = dbClient;
    db = database;

    //Get sites URLs
    const site_docs = await db.collection('sites').find().toArray();

    // Flatten all URL entries
    const rawUrls = site_docs.flatMap(site => site.urls || []);
    const cleanedUrls = rawUrls.map(url => url.trim()).filter(Boolean);

    // Extract unique domains only (drop any path after slash)
    const domains = [...new Set(
      cleanedUrls.map(url => url.split('/')[0].toLowerCase())
    )];

    
    return res.json({ domains });

  } catch (err) {
    console.error('Error geting domains information:', err);
    return res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

});


module.exports = router;