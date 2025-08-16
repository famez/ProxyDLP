// db.js
const { MongoClient } = require('mongodb');

const mongoUri = process.env.MONGO_URI;

async function connectToDB() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  const db = client.db('ProxyDLP');

  return { client, db };
}

module.exports = { connectToDB };
