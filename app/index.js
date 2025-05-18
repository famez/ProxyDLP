const express = require('express');
const { MongoClient } = require('mongodb');
const path = require('path');


const app = express();
const PORT = 80;
const mongoUri = process.env.MONGO_URI;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


app.get('/', async (req, res) => {
  try {
    const client = new MongoClient(mongoUri);
    await client.connect();
    const db = client.db('proxyGPT');
    const collections = await db.listCollections().toArray();
    await client.close();

    res.send(`Connected to MongoDB. Collections: ${collections.map(c => c.name).join(', ')}`);
  } catch (err) {
    res.status(500).send('Error connecting to MongoDB: ' + err.message);
  }
});

app.get('/terminal', (req, res) => {
  res.render('terminal'); // renders views/terminal.ejs
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
