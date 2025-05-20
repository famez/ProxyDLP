const express = require('express');
const { MongoClient } = require('mongodb');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');


const app = express();
const PORT = 80;
const mongoUri = process.env.MONGO_URI;

app.set('view engine', 'ejs');
app.use(expressLayouts);
app.use(express.static('public'));
app.set('views', path.join(__dirname, 'views'));


app.get('/', (req, res) => {
  res.render('welcome', { title: 'Welcome' });
});


app.get('/users', async (req, res) => {

  try {
      const client = new MongoClient(mongoUri);
      await client.connect();
      const db = client.db('proxyGPT');
      const collection = db.collection('events');

      const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);

      const recentUsers = await collection.aggregate([
        { $match: { timestamp: { $gte: thirtyMinutesAgo } } },
        { $group: { _id: "$user" } }
      ]).toArray();

      // Map to get an array of emails
      const users = recentUsers.map(u => u._id);

      res.render('users', { title: 'Users', users });



    } catch (err) {
      res.status(500).send('Error connecting to MongoDB: ' + err.message);
    }

});

app.get('/terminal', (req, res) => {
  res.render('terminal', { title: 'Terminal' }); // renders views/terminal.ejs
});

app.get('/user/:username', (req, res) => {
  const username = req.params.username;
  const actions = [
    { timestamp: '2025-05-19 10:23', title: 'Logged In', description: 'User logged into the system.' },
    { timestamp: '2025-05-19 10:30', title: 'Updated Profile', description: 'Changed profile picture and bio.' },
    // more actions...
  ];

  // Fetch user data if needed
  res.render('user', { title: username + ' activity', username, actions });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
