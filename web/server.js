const express = require('express');
const { MongoClient } = require('mongodb');
const { ObjectId } = require('mongodb');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const authMiddleware = require('./middleware/authMiddleware');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');



const app = express();
const PORT = 3000;
const mongoUri = process.env.MONGO_URI;

app.set('view engine', 'ejs');
app.use(expressLayouts);
app.use(express.static('public'));
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());


// Load the protobuf
const packageDefinition = protoLoader.loadSync(
  path.resolve(__dirname, 'monitor.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  }
);

const proto = grpc.loadPackageDefinition(packageDefinition).monitor;

// Create the client
const gRPC_client = new proto.Monitor('monitor:50051', grpc.credentials.createInsecure());

function isValidRegex(pattern) {
  try {
    new RegExp(pattern);
    return true;
  } catch (e) {
    return false;
  }
}

function isStrongPassword(password) {
  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$/;
  return strongPasswordRegex.test(password);
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

app.get('/', authMiddleware, (req, res) => {
  res.render('welcome', { title: 'Welcome' });
});


app.get('/dashboard', authMiddleware, async (req, res) => {

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

      res.render('dashboard', { title: 'Users', users });

      await client.close();

    } catch (err) {
      res.status(500).send('Error connecting to MongoDB: ' + err.message);
    }

});

app.get('/terminal', authMiddleware, (req, res) => {
  res.render('terminal', { title: 'Terminal' }); // renders views/terminal.ejs
});

app.get('/user/:username', authMiddleware, async (req, res) => {

  const username = req.params.username;

  try {
      
    events = await getUserEvents(username);

    // Fetch user data if needed
    res.render('user', { title: username + ' activity', username, events });


  } catch (err) {
      res.status(500).send('Error connecting to MongoDB: ' + err.message);
    }
  
});

app.get('/rules', authMiddleware, async (req, res) => {

  regexRules = await getRegexRules();
  cossimrules = await getTopicMatchRules();

  res.render('rules', { title: "Rules Manager", regexRules, cossimrules });
});


app.post('/rules/regex/add', authMiddleware, async (req, res) => {
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


app.post('/rules/topic/add', authMiddleware, async (req, res) => {
  const { name, pattern } = req.body;

  if (!name || !pattern) {
    return res.status(400).send('Name and pattern are required.');
  }

  try {
    const { client, db } = await connectToDB();
    const result = await db.collection('cos_sim_rules').insertOne({ name: name, pattern: pattern });
    gRPC_client.TopicRuleAdded({ id: result.insertedId }, (err, response) => {
      if (err) {
        console.error('Error:', err);
      } else {
        console.log('TopicRuleAdded. Result:', response.message);
      }
    });

    res.redirect('/rules');
  } catch (err) {
    if (err.code === 11000) {
      console.error('Error adding topic rule, key duplicated');
      return res.status(400).send('Cannot add rule, because name is duplicated');  
    }

    console.error('Error adding topic rule:', err);
    return res.status(500).send('Internal Server Error');
  }
});


app.post('/rules/:type/delete/:id', authMiddleware, async (req, res) => {
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

app.get('/rules/:type/edit/:id', authMiddleware, async (req, res) => {
  const { type, id } = req.params;
  const collection = type === 'regex' ? 'regex_rules' : 'cos_sim_rules';

  try {
    const { client, db } = await connectToDB();
    const rule = await db.collection(collection).findOne({ _id: new ObjectId(id) });
    if (!rule) return res.status(404).send('Rule not found');
    const render_page = type === 'regex' ? 'edit_regex_rule' : 'edit_topic_rule';
    res.render(render_page, {title: "Edit Rule",  rule });
  } catch (err) {
    res.status(500).send('Error loading rule: ' + err);
  }
});


app.post('/rules/:type/edit/:id', authMiddleware, async (req, res) => {
  const { type, id } = req.params;
  const { name, pattern } = req.body;

  // Optional regex validation for regex rules
  if (type === 'regex') {
    if (!isValidRegex(pattern)) {
      return res.status(400).send('Invalid regex pattern.');
    }
  }

  try {

    const { client, db } = await connectToDB();

    if(type === 'regex') {
      await db.collection('regex_rules').replaceOne(
        { _id: new ObjectId(id) },
        { [name]: pattern }
      );
    } else {
      await db.collection('cos_sim_rules').replaceOne(
        { _id: new ObjectId(id) },
        { name: name, pattern: pattern }
      );
    }
    
    res.redirect('/rules');
  } catch (err) {
    res.status(500).send('Error updating rule');
  }
});

app.get('/uploads/:file', authMiddleware, (req, res) => {
  
  const filepath = req.params.file;
  const filename = req.query.name;
  console.log("Getting file..." + filepath);
  res.download("/uploads/" + filepath, filename); // second argument is optional

});

app.get('/domains', authMiddleware, async (req, res) => {

  try {
    const { client, db } = await connectToDB();
    const domains = await db.collection("domains").find().toArray();
    res.render('domains', { title: "Domains", domains });
  } catch (err) {
    res.status(500).send('Error loading rule: ' + err);
  }
  
});

app.post('/domains/delete/:id', authMiddleware, async (req, res) => {
  
  const id = req.params.id;

  try {
    const { client, db } = await connectToDB();
    await db.collection("domains").deleteOne({ _id: new ObjectId(id) });
    res.redirect('/domains');
  } catch (err) {
    console.error('Error deleting domain:', err);
    res.status(500).send('Error deleting domain');
  }
});

app.post('/domains/add', authMiddleware, async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).send('Domain is required.');
  }

  const regex = /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i;

  if (!regex.test(domain)) {
    return res.status(400).send('The value provided is not a domain');
  }

  try {
    const { client, db } = await connectToDB();
    await db.collection('domains').insertOne({ content: domain });
    res.redirect('/domains');
  } catch (err) {
    console.error('Error adding domain:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/login', (req, res) => res.render('login', { layout: false }));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const { client, db } = await connectToDB();
    const user = await db.collection('users').findOne({ username: username });
    if (!user) return res.status(401).redirect('/login');
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).redirect('/login');
    const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/');

  } catch (err) {
    console.error('Error in login:', err);
    res.status(500).send('Internal Server Error');
  }

});

app.get('/logout', authMiddleware, (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.get('/user-management', authMiddleware, async (req, res) => {
  const { client, db } = await connectToDB();
  const users = await db.collection('users').find().toArray();  
  res.render('user-management', {
    title: "User management",
    users
  });
});


app.post('/add-user', authMiddleware, async (req, res) => {
  const { username, password } = req.body;
  try {
    const { client, db } = await connectToDB();
    const user = await db.collection('users').findOne({ username: username });


    if (user) {
      return res.status(400).send("User already exists.");
    }

    if (!isStrongPassword(password)) {
      return res.status(400).send("Password must be at least 12 characters long and include uppercase, lowercase, number, and special character.");
    }

    await db.collection('users').insertOne({ username: username, password: await bcrypt.hash(password, 10) });
    res.redirect('/user-management');

  } catch (err) {
    console.error('Error in add-user:', err);
    res.status(500).send('Internal Server Error');
  }

});

app.post('/update-password', authMiddleware, async (req, res) => {

  const { username, newPassword } = req.body;
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  
  try {
    const { client, db } = await connectToDB();
    const user = await db.collection('users').findOne({ username: username });

    if (!user) {
      return res.status(400).send("User does not exist.");
    }

    if (!isStrongPassword(newPassword)) {
      return res.status(400).send("Password must be at least 12 characters long and include uppercase, lowercase, number, and special character.");
    }

    await db.collection('users').updateOne(
          { username: username },
          { $set: { password: hashedPassword } }
    );
    res.redirect('/user-management');

  } catch (err) {
    console.error('Error in update-password:', err);
    res.status(500).send('Internal Server Error');
  }

});

app.post('/delete-user', authMiddleware, async (req, res) => {
  const { username } = req.body;

  // Prevent self-deletion
  if (username === res.locals.username) {
    return res.status(400).send("You cannot delete your own account.");
  }

  try {
    const { client, db } = await connectToDB();
    const result = await db.collection('users').deleteOne({ username: username });

    if (result.deletedCount === 0) {
      return res.status(404).send("User not found.");
    }

    res.redirect('/user-management');
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).send("Internal Server Error");
  }
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
