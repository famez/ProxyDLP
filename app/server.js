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


async function connectToDB() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  const db = client.db('proxyGPT');
  const collection = db.collection('events');
  
  return { client, collection };
}

async function getUserEvents(username) {
  const { client, collection } = await connectToDB();
  const events = await collection.find({ user: username }).toArray();
  await client.close();
  return events;
}


app.get('/', (req, res) => {
  res.render('welcome', { title: 'Welcome' });
});


app.get('/users', async (req, res) => {

  try {
      
      const { client, collection } = await connectToDB();

      const thirtyMinutesAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

      const recentUsers = await collection.aggregate([
        { $match: { timestamp: { $gte: thirtyMinutesAgo } } },
        { $group: { _id: "$user" } }
      ]).toArray();

      // Map to get an array of emails
      const users = recentUsers.map(u => u._id);

      //console.log("Users: "+ users);

      res.render('users', { title: 'Users', users });

      await client.close();

    } catch (err) {
      res.status(500).send('Error connecting to MongoDB: ' + err.message);
    }

});

app.get('/terminal', (req, res) => {
  res.render('terminal', { title: 'Terminal' }); // renders views/terminal.ejs
});

app.get('/user/:username', async (req, res) => {

  const username = req.params.username;

  try {
      
    events = await getUserEvents(username);

    // Fetch user data if needed
    res.render('user', { title: username + ' activity', username, events });


  } catch (err) {
      res.status(500).send('Error connecting to MongoDB: ' + err.message);
    }
  
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
