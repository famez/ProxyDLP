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

async function getRegexRules() {
  const { client, db } = await connectToDB();
  const regexRules = await db.collection('regex_rules').find().toArray();
  await client.close();
  return regexRules;
}

async function getTopicMatchRules() {
  const { client, db } = await connectToDB();
  const topicRules = await db.collection('topic_rules').find().toArray();
  await client.close();
  return topicRules;
}

app.get('/', authMiddleware, (req, res) => {
  res.render('welcome', { title: 'Welcome' });
});


app.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    res.render('dashboard', { title: 'Dashboard' });
  } catch (err) {
    console.error('Error rendering dashboard:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/terminal', authMiddleware, (req, res) => {
  res.render('terminal', { title: 'Terminal' }); // renders views/terminal.ejs
});

app.get('/explore', authMiddleware, async (req, res) => {

  const {
    start, end, user, site, rational,
    filename, filetype, content, leak, order = 'desc'
  } = req.query;

  const query = {};

  // Date filter
  if (start || end) {
    query.timestamp = {};
    if (start) query.timestamp.$gte = new Date(start);
    if (end) query.timestamp.$lte = new Date(end);
  }

  // Simple text filters with regex (case insensitive)
  if (user) query.user = { $regex: new RegExp(user, 'i') };
  if (site) query.site = { $regex: new RegExp(site, 'i') };
  if (rational) query.rational = { $regex: new RegExp(rational, 'i') };
  if (content) query.content = { $regex: new RegExp(content, 'i') };
  if (filename) query.filename = { $regex: new RegExp(filename, 'i') };
  if (filetype) query.content_type = { $regex: new RegExp(filetype, 'i') };
  

  const sort = { timestamp: order === 'asc' ? 1 : -1 };

  const limit = parseInt(req.query.limit, 10) || 50;
  const page = parseInt(req.query.page, 10) || 1;
  const skip = (page - 1) * limit;



  let client;
  try {
    ({ client, db } = await connectToDB());
    const event_collection = db.collection('events');

    if (leak) {
      const leakRegex = new RegExp(leak, 'i');

      // Use aggregation pipeline when filtering by leak keys
      const pipeline = [
        { $match: query },
        { $addFields: {
            leakRegexArray: { $objectToArray: "$leak.regex" },
            leakNerArray: { $objectToArray: "$leak.ner" }
          }
        },
        { $match: {
            $or: [
              { "leakRegexArray.v": { $regex: leakRegex } },
              { "leakNerArray.k": { $regex: leakRegex } },
              { "leak.topic": leakRegex }
            ]
          }
        },
        { $sort: sort },
        { $skip: skip },
        { $limit: limit }
      ];

      const events = await event_collection.aggregate(pipeline).toArray();

      res.render('explore', { title: 'Explore', events, filters: req.query });
    } else {
      // If no leak filter, simple find + sort
      const events = await event_collection.find(query).sort(sort).skip(skip).limit(limit).toArray();

      res.render('explore', { title: 'Explore', events, filters: req.query });
    }
  } catch (err) {
    console.error('Error in /explore:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.get('/rules', authMiddleware, async (req, res) => {
  try {
    regexRules = await getRegexRules();
    topicRules = await getTopicMatchRules();
    res.render('rules', { title: "Rules Manager", regexRules, topicRules });
  } catch (err) {
    console.error('Error loading rules:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/rules/regex/add', authMiddleware, async (req, res) => {
  const { name, pattern } = req.body;

  if (!name || !pattern) {
    return res.status(400).send('Name and pattern are required.');
  }

  if (!isValidRegex(pattern)) {
    return res.status(400).send('Invalid regex pattern.');
  }

  let client;
  try {
    ({ client, db } = await connectToDB());
    await db.collection('regex_rules').insertOne({ [name]: pattern });
    res.redirect('/rules');
  } catch (err) {
    console.error('Error adding regex rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});


app.post('/rules/topic/add', authMiddleware, async (req, res) => {
  const { name, pattern } = req.body;

  if (!name || !pattern) {
    return res.status(400).send('Name and pattern are required.');
  }
  let client;
  try {
    ({ client, db } = await connectToDB());
    const result = await db.collection('topic_rules').insertOne({ name: name, pattern: pattern });
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
  } finally {
    if (client) await client.close();
  }
});


app.post('/rules/:type/delete/:id', authMiddleware, async (req, res) => {
  const { type, id } = req.params;

  const collection = type === 'regex' ? 'regex_rules' : 'topic_rules';
  let client;
  try {
    ({ client, db } = await connectToDB());
    await db.collection(collection).deleteOne({ _id: new ObjectId(id) });
    res.redirect('/rules');
  } catch (err) {
    console.error('Error deleting rule:', err);
    res.status(500).send('Error deleting rule');
  } finally {
    if (client) await client.close();
  }
});

app.get('/rules/:type/edit/:id', authMiddleware, async (req, res) => {
  const { type, id } = req.params;
  const collection = type === 'regex' ? 'regex_rules' : 'topic_rules';
  let client;
  try {
    ({ client, db } = await connectToDB());
    const rule = await db.collection(collection).findOne({ _id: new ObjectId(id) });
    if (!rule) return res.status(404).send('Rule not found');
    const render_page = type === 'regex' ? 'edit_regex_rule' : 'edit_topic_rule';
    res.render(render_page, {title: "Edit Rule",  rule });
  } catch (err) {
    console.error('Error loading rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
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
  let client;
  try {

    ({ client, db } = await connectToDB());

    if(type === 'regex') {
      await db.collection('regex_rules').replaceOne(
        { _id: new ObjectId(id) },
        { [name]: pattern }
      );
    } else {
      await db.collection('topic_rules').replaceOne(
        { _id: new ObjectId(id) },
        { name: name, pattern: pattern }
      );
      
      gRPC_client.TopicRuleAdded({ id: id }, (err, response) => {
        if (err) {
          console.error('Error:', err);
        } else {
          console.log('TopicRuleAdded. Result:', response.message);
        }
      });
    }
    
    res.redirect('/rules');
  } catch (err) {
    res.status(500).send('Error updating rule');
  } finally {
    if (client) await client.close();
  }
});
// Secure file download endpoint to prevent path traversal attacks
app.get('/uploads/:file', authMiddleware, (req, res) => {
  const file = req.params.file;
  const filename = req.query.name;

  // Only allow safe characters
  if (!/^[\w\-\.]+$/.test(file)) {
    return res.status(400).send('Invalid file name.');
  }

  // Resolve absolute paths
  const uploadsDir = '/uploads';
  const filePath = path.resolve(uploadsDir, file);

  // Ensure path stays inside uploadsDir
  if (!filePath.startsWith(uploadsDir + path.sep)) {
    return res.status(403).send('Access denied.');
  }

  res.download(filePath, filename, (err) => {
    if (err) {
      console.error('File download error:', err);
      res.status(404).send('File not found.');
    }
  });
});


app.get('/domains', authMiddleware, async (req, res) => {
  let client;
  try {
    ({ client, db } = await connectToDB());
    const domains = await db.collection("domains").find().toArray();
    res.render('domains', { title: "Domains", domains });
  } catch (err) {
    console.error('Error loading domains:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/domains/delete/:id', authMiddleware, async (req, res) => {
  const id = req.params.id;
  let client;
  try {
    ({ client, db } = await connectToDB());
    await db.collection("domains").deleteOne({ _id: new ObjectId(id) });
    res.redirect('/domains');
  } catch (err) {
    console.error('Error deleting domain:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
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
  let client;
  try {
    ({ client, db } = await connectToDB());
    await db.collection('domains').insertOne({ content: domain });
    res.redirect('/domains');
  } catch (err) {
    console.error('Error adding domain:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.get('/login', (req, res) => res.render('login', { layout: false }));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  let client;
  try {
    ({ client, db } = await connectToDB());
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
  } finally {
    if (client) await client.close();
  }

});

app.get('/logout', authMiddleware, (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.get('/user-management', authMiddleware, async (req, res) => {
  let client;
  try {
    ({ client, db } = await connectToDB());
    const users = await db.collection('users').find().toArray();  
    res.render('user-management', {
      title: "User management",
      users
    });
  } catch (err) {
    console.error('Error loading user management:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});


app.post('/add-user', authMiddleware, async (req, res) => {
  const { username, password } = req.body;
  let client;
  try {
    ({ client, db } = await connectToDB());
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
    console.error('Error adding user:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/update-password', authMiddleware, async (req, res) => {
  const { username, newPassword } = req.body;
  let client;
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    ({ client, db } = await connectToDB());
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
    console.error('Error updating password:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/delete-user', authMiddleware, async (req, res) => {
  const { username } = req.body;

  // Prevent self-deletion
  if (username === res.locals.username) {
    return res.status(400).send("You cannot delete your own account.");
  }
  let client;
  try {
    ({ client, db } = await connectToDB());
    const result = await db.collection('users').deleteOne({ username: username });
    if (result.deletedCount === 0) {
      return res.status(404).send("User not found.");
    }
    res.redirect('/user-management');
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).send("Internal Server Error");
  } finally {
    if (client) await client.close();
  }
});

app.get('/api/options', authMiddleware, async (req, res) => {
  const { field, startsWith = '' } = req.query;
  if (!field) return res.status(400).json({ error: 'Missing field' });
  const allowedFields = ['user', 'site', 'rational', 'filename', 'content_type'];
  if (!allowedFields.includes(field)) return res.status(400).json({ error: 'Invalid field' });
  let client;
  try {
    ({ client, db } = await connectToDB());
    const events_collection = db.collection('events');
    const pipeline = [
      { $match: { [field]: { $regex: `^${startsWith}`, $options: '' } } },
      { $group: { _id: `$${field}` } }
    ];
    const results = await events_collection.aggregate(pipeline).toArray();
    const values = results.map(r => r._id).filter(Boolean);
    await client.close();
    res.json(values);
  } catch (err) {
    console.error('Error fetching options:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    if (client) await client.close();
  }
});

app.get('/event/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  let client;
  try {
    ({ client, db } = await connectToDB());
    const events_collection = db.collection('events');
    const event = await events_collection.findOne({ _id: new ObjectId(id) });
    if (!event) return res.status(404).send('Event not found');
    res.render('event-detail', { title: "Event detail", event });
  } catch (err) {
    console.error('Error fetching event:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.get('/stats', authMiddleware, async (req, res) => {

  let client;

  try {

    ({ client, db } = await connectToDB());

    const riskyEvents = await db.collection('events').aggregate([
      // Step 1: Extract max score from leak.topic array
      {
        $addFields: {
          maxScore: { 
            $max: {
              $map: {
                input: { $ifNull: ["$leak.topic", []] }, // safely get leak.topic
                as: "t",
                in: "$$t.score"
              }
            }
          }
        }
      },
      // Step 2: Filter events that have a valid maxScore
      {
        $match: {
          maxScore: { $type: "number" }
        }
      },
      // Step 3: Sort by maxScore descending
      {
        $sort: { maxScore: -1 }
      },
      // Step 4: Limit to top 10 events
      {
        $limit: 10
      },
      // Step 5: Find the topic object with the maxScore inside leak.topic
      {
        $addFields: {
          topTopic: {
            $arrayElemAt: [
              {
                $filter: {
                  input: "$leak.topic",
                  as: "t",
                  cond: { $eq: ["$$t.score", "$maxScore"] }
                }
              },
              0
            ]
          }
        }
      },
      // Step 6: Project the fields you want to return
      {
        $project: {
          user: 1,
          timestamp: 1,
          site: 1,
          content: 1,
          cos_score: "$maxScore",
          topicName: "$topTopic.name",
        }
      }
    ]).toArray();

    const topicStats = await db.collection('events').aggregate([
      { $unwind: '$leak.topic' },                                
      { $group: { _id: '$leak.topic.name', count: { $sum: 1 } } }, 
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]).toArray();



    const toolUsage = await db.collection('events').aggregate([
      { $group: { _id: '$site', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]).toArray();



    const userStats = await db.collection('events').aggregate([
      // Step 1: Extract max score from leak.topic
      {
        $addFields: {
          cos_score: {
            $max: {
              $map: {
                input: { $ifNull: ["$leak.topic", []] },
                as: "t",
                in: "$$t.score"
              }
            }
          }
        }
      },
      // Step 2: Filter events with a valid score
      {
        $match: {
          cos_score: { $type: "number" }
        }
      },
      // Step 3: Group by user and compute stats
      {
        $group: {
          _id: '$user',
          count: { $sum: 1 },
          avg_score: { $avg: "$cos_score" },
          max_score: { $max: "$cos_score" }
        }
      },
      // Step 4: Sort and limit
      {
        $sort: { max_score: -1 }
      },
      {
        $limit: 5
      }
    ]).toArray();



    const trendData = await db.collection('events').aggregate([
      // Step 1: Compute max score from leak.topic
      {
        $addFields: {
          cos_score: {
            $max: {
              $map: {
                input: { $ifNull: ["$leak.topic", []] },
                as: "t",
                in: "$$t.score"
              }
            }
          }
        }
      },
      // Step 2: Filter valid scores
      {
        $match: {
          cos_score: { $type: "number" }
        }
      },
      // Step 3: Group by date string
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
          count: { $sum: 1 },
          avg_score: { $avg: "$cos_score" }
        }
      },
      // Step 4: Sort by date
      {
        $sort: { "_id": 1 }
      }
    ]).toArray();



      const regexLabelStats = await db.collection('events').aggregate([
        {
          $project: {
            regexLabels: { $objectToArray: "$leak.regex" }
          }
        },
        { $unwind: "$regexLabels" },
        { $group: { _id: "$regexLabels.v", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 50 }
      ]).toArray();


      const regexHeavyEvents = await db.collection('events').aggregate([
        {
          $match: {
            "leak.regex": { $type: "object" }
          }
        },
        {
          $addFields: {
            regexArray: { $objectToArray: "$leak.regex" },
            regexCount: { $size: { $objectToArray: "$leak.regex" } }
          }
        },
    
        {
          $sort: { regexCount: -1 }
        },
        {
          $limit: 10
        },
        {
          $project: {
            user: 1,
            timestamp: 1,
            site: 1,
            content: 1,
            regexCount: 1,
          }
        }
      ]).toArray();

      const topMatchedWords = await db.collection('events').aggregate([
        {
          $match: {
            "leak.regex": { $type: "object" }
          }
        },
        {
          $project: {
            regexArray: { $objectToArray: "$leak.regex" }
          }
        },
        { $unwind: "$regexArray" }, // regexArray.k = matched word, regexArray.v = regex name
        {
          $group: {
            _id: {
              word: "$regexArray.k",
              name: "$regexArray.v" // now this is the label
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]).toArray();
  
    await client.close();

    res.render('stats', {title: "Statistics", 
      riskyEvents,
      topicStats,
      toolUsage,
      userStats,
      trendDates: trendData.map(d => d._id),
      trendCounts: trendData.map(d => d.count),
      regexLabelStats,
      regexHeavyEvents,
      topMatchedWords
    });

  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).send('Internal Server Error');
  }
  finally {
    if (client) await client.close();
  }

});

app.post('/mark-sensitive', authMiddleware, async (req, res) => {
  const { event_id } = req.body;
  console.log('Marking event as sensitive:', event_id);

  let client;
  try {
    ({ client, db } = await connectToDB());
    
    // Update the event to mark it as sensitive
    result = await db.collection('events').updateOne(
      { _id: new ObjectId(event_id) },
      { $set: { sensitive: true } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).send('Event not found or already marked as sensitive');
    }
    
    console.log('Event marked as sensitive:', event_id);

    gRPC_client.EventAddedToMonitor({ id: event_id }, (err, response) => {
      if (err) {
        console.error('Error:', err);
      } else {
        console.log('EventAddedToMonitor. Result:', response.message);
      }
     });

  res.status(200).send('Event marked as sensitive'); // Placeholder response

  } catch (err) {
    console.error('Error marking event as sensitive:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
  

});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
