// agents.js
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { connectToDB } = require('./db');


router.get('/register', async (req, res) => {

  console.log('Register received');

  //For the moment, no security

  // Generate a GUID
  const guid = uuidv4();

  let client;

  try {
    ({ client, db } = await connectToDB());

    const result = await db.collection('agents').insertOne({ guid });

    console.log('Agent registered');

  } catch (err) {
    console.error('Error updating agent information:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

  // Return it in a JSON object
  res.json({ guid });


});


// Heartbeat endpoint
router.post('/heartbeat', async (req, res) => {
  console.log('Heartbeat received:', req.body);


  // Destructure expected fields
  const { computer_name, os_version, user, ip_addresses, agent_version } = req.body;

  console.log(`--> Computer: ${computer_name}`);
  console.log(`--> OS: ${os_version}`);
  console.log(`--> User: ${user}`);
  console.log(`--> IP(s): ${ip_addresses}`);
  console.log(`--> Agent Version: ${agent_version}`);

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;


  let client;

  try {
    ({ client, db } = await connectToDB());

  await db.collection('agents').updateOne(
    { ip }, // find by IP
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