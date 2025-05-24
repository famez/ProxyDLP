const express = require('express');
const { MongoClient } = require('mongodb');
const { ObjectId } = require('mongodb');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');


const app = express();
const PORT = 80;
const mongoUri = process.env.MONGO_URI;

app.set('view engine', 'ejs');
app.use(expressLayouts);
app.use(express.static('public'));
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

function isValidRegex(pattern) {
  try {
    new RegExp(pattern);
    return true;
  } catch (e) {
    return false;
  }
}


async function connectToDB() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  const db = client.db('proxyGPT');
  
  return { client, db };
}

async function getUserEvents(username) {
  const { client, db } = await connectToDB();
  const events = await db.collection('events').find({ user: username }).toArray();
  await client.close();
  return events;
}

async function getRegexRules() {
  const { client, db } = await connectToDB();
  const regexRules = await db.collection('regex_rules').find().toArray();
  await client.close();
  return regexRules;
}

async function getTopicMatchRules() {
  const { client, db } = await connectToDB();
  const topicRules = await db.collection('cos_sim_rules').find().toArray();
  await client.close();
  return topicRules;
}

app.get('/', (req, res) => {
  res.render('welcome', { title: 'Welcome' });
});


app.get('/users', async (req, res) => {

  try {
      
      const { client, db } = await connectToDB();


      const thirtyMinutesAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

      const recentUsers = await db.collection('events').aggregate([
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

app.get('/rules', async (req, res) => {

  regexRules = await getRegexRules();
  cossimrules = await getTopicMatchRules();

  res.render('rules', { title: "Rules Manager", regexRules, cossimrules });
});


app.post('/rules/regex/add', async (req, res) => {
  const { name, pattern } = req.body;

  if (!name || !pattern) {
    return res.status(400).send('Name and pattern are required.');
  }

  if (!isValidRegex(pattern)) {
    return res.status(400).send('Invalid regex pattern.');
  }

  try {
    const { client, db } = await connectToDB();
    await db.collection('regex_rules').insertOne({ [name]: pattern });
    res.redirect('/rules');
  } catch (err) {
    console.error('Error adding regex rule:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/rules/topic/add', async (req, res) => {
  const { name, pattern } = req.body;

  if (!name || !pattern) {
    return res.status(400).send('Name and pattern are required.');
  }

  try {
    const { client, db } = await connectToDB();
    await db.collection('cos_sim_rules').insertOne({ [name]: pattern });
    res.redirect('/rules');
  } catch (err) {
    console.error('Error adding text rule:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/rules/:type/delete/:id', async (req, res) => {
  const { type, id } = req.params;

  const collection = type === 'regex' ? 'regex_rules' : 'cos_sim_rules';

  try {
    const { client, db } = await connectToDB();
    await db.collection(collection).deleteOne({ _id: new ObjectId(id) });
    res.redirect('/rules');
  } catch (err) {
    console.error('Error deleting rule:', err);
    res.status(500).send('Error deleting rule');
  }
});

app.get('/rules/:type/edit/:id', async (req, res) => {
  const { type, id } = req.params;
  const collection = type === 'regex' ? 'regex_rules' : 'cos_sim_rules';

  try {
    const { client, db } = await connectToDB();
    const rule = await db.collection(collection).findOne({ _id: new ObjectId(id) });
    if (!rule) return res.status(404).send('Rule not found');
    res.render('edit_rule', {title: "Edit Rule",  rule, type });
  } catch (err) {
    res.status(500).send('Error loading rule: ' + err);
  }
});


app.post('/rules/:type/edit/:id', async (req, res) => {
  const { type, id } = req.params;
  const { name, pattern } = req.body;
  const collection = type === 'regex' ? 'regex_rules' : 'cos_sim_rules';

  // Optional regex validation for regex rules
  if (type === 'regex') {
    if (!isValidRegex(pattern)) {
      return res.status(400).send('Invalid regex pattern.');
    }
  }

  try {
    const { client, db } = await connectToDB();
    await db.collection(collection).replaceOne(
      { _id: new ObjectId(id) },
      { [name]: pattern }
    );
    res.redirect('/rules');
  } catch (err) {
    res.status(500).send('Error updating rule');
  }
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
