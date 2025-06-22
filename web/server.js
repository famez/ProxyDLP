const express = require('express');
const { MongoClient } = require('mongodb');
const { ObjectId } = require('mongodb');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const authMiddleware = require('./middleware/authMiddleware');
const requirePermission = require('./middleware/requirePermission');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const multer = require('multer');


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

const upload = multer({ dest: '/uploads/' });


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

app.get('/terminal', authMiddleware, requirePermission("mitmterminal"), (req, res) => {
  res.render('terminal', { title: 'Terminal' }); // renders views/terminal.ejs
});

app.get('/explore', authMiddleware, requirePermission("events"), async (req, res) => {

  const {
    start, end, user, site, rational,
    filename, filetype, content, leak, order = 'desc',
    playground
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
  if (site) {
    query.site = { $regex: new RegExp(site, 'i') };
  } else if (playground !== '1') {    //Exclude Playground site if not specified
    query.site = { $ne: 'Playground' };
  }

  if (rational) query.rational = { $regex: new RegExp(rational, 'i') };
  if (content) query.content = { $regex: new RegExp(content, 'i') };
  if (filename) query.filename = { $regex: new RegExp(filename, 'i') };
  if (filetype) query.content_type = { $regex: new RegExp(filetype, 'i') };
  

  const sort = { timestamp: order === 'asc' ? 1 : -1 };

  const limit = parseInt(req.query.limit, 10) || 10;
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

app.get('/rules', authMiddleware, requirePermission("rules"), (req, res) => {
  res.render('rules-menu', { title: "Rules Dashboard" });
});


// ========== View Routes ==========

app.get('/rules/regex', authMiddleware, requirePermission("rules"), async (req, res) => {
  try {
    const regexRules = await getRegexRules();
    res.render('regex-rules', { title: "Regex Rules", regexRules });
  } catch (err) {
    console.error('Error loading regex rules:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/rules/topic', authMiddleware, requirePermission("rules"), async (req, res) => {
  try {
    const topicRules = await getTopicMatchRules();
    res.render('topic-rules', { title: "Topic Match Rules", topicRules });
  } catch (err) {
    console.error('Error loading topic rules:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/rules/yara', authMiddleware, requirePermission("rules"), async (req, res) => {
  try {
    const { client, db } = await connectToDB();
    const yaraRules = await db.collection('yara_rules').find().toArray();
    await client.close();
    res.render('yara-rules', { title: "YARA Rules", yaraRules });
  } catch (err) {
    console.error('Error loading YARA rules:', err);
    res.status(500).send('Internal Server Error');
  }
});


// ========== Add Routes ==========

app.post('/rules/regex/add', authMiddleware, requirePermission("rules"), async (req, res) => {
  const { name, pattern } = req.body;
  if (!name || !pattern || !isValidRegex(pattern)) {
    return res.status(400).send('Invalid input or regex.');
  }

  let client;
  try {
    ({ client, db } = await connectToDB());
    const result = await db.collection('regex_rules').insertOne({ [name]: pattern });
    gRPC_client.RegexRuleAdded({ id: result.insertedId }, () => {});
    res.redirect('/rules/regex');
  } catch (err) {
    console.error('Error adding regex rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/rules/topic/add', authMiddleware, requirePermission("rules"), async (req, res) => {
  const { name, pattern } = req.body;
  if (!name || !pattern) {
    return res.status(400).send('Name and pattern are required.');
  }

  let client;
  try {
    ({ client, db } = await connectToDB());
    const result = await db.collection('topic_rules').insertOne({ name, pattern });
    gRPC_client.TopicRuleAdded({ id: result.insertedId }, () => {});
    res.redirect('/rules/topic');
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).send('Name is duplicated');
    }
    console.error('Error adding topic rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/rules/yara/add', authMiddleware, requirePermission("rules"), async (req, res) => {
  const { name, content } = req.body;
  if (!name || !content) {
    return res.status(400).send('Name and content are required.');
  }

  //Send gRPC notification to monitor as it can check if the rule is valid
  const result = gRPC_client.YaraRuleAdded({ name: name, content: content }, (err, response) => {
    if (err) {
      console.error('gRPC YaraRuleAdded error:', err);
      console.error('Error adding YARA rule:', err);
      res.status(500).send('Internal Server Error');
    } else {
      console.log('gRPC YaraRuleAdded response:', response);

      // If the rule was added successfully, return to the YARA rules page
      if (response.result == 0) {
        res.redirect('/rules/yara');
      } else {
        // If there was an error, send the error message
        console.log('Invalid YARA rule');
        res.status(400).send('Invalid YARA rule:');
      }

    }
  });  
  
});


// ========== Delete Route (Shared) ==========

app.post('/rules/:type/delete/:id', authMiddleware, requirePermission("rules"), async (req, res) => {
  const { type, id } = req.params;
  const validTypes = ['regex', 'topic', 'yara'];
  if (!validTypes.includes(type)) return res.status(400).send('Invalid rule type.');

  let client;
  try {
    ({ client, db } = await connectToDB());

    if (type === 'topic') {
      // Notify gRPC service about topic rule deletion
      gRPC_client.TopicRuleRemoved({ id }, () => {});   //Monitor service will handle the deletion from the database
    } else if (type === 'yara') { 
      // Notify gRPC service about YARA rule deletion
      await db.collection(`${type}_rules`).deleteOne({ _id: new ObjectId(id) });
      gRPC_client.YaraRuleRemoved({ id }, () => {});
    } else if (type === 'regex') {
      // Notify gRPC service about regex rule deletion
      await db.collection(`${type}_rules`).deleteOne({ _id: new ObjectId(id) });
      gRPC_client.RegexRuleRemoved({ id }, () => {});
    }

    res.redirect(`/rules/${type}`);
  } catch (err) {
    console.error(`Error deleting ${type} rule:`, err);
    res.status(500).send('Error deleting rule');
  } finally {
    if (client) await client.close();
  }
});


// ========== Edit GET Route (Shared) ==========

app.get('/rules/:type/edit/:id', authMiddleware, requirePermission("rules"), async (req, res) => {
  const { type, id } = req.params;
  const collectionMap = {
    regex: 'regex_rules',
    topic: 'topic_rules',
    yara: 'yara_rules'
  };

  const pageMap = {
    regex: 'edit_regex_rule',
    topic: 'edit_topic_rule',
    yara: 'edit_yara_rule'
  };

  if (!collectionMap[type]) return res.status(400).send('Invalid rule type.');

  let client;
  try {
    ({ client, db } = await connectToDB());
    const rule = await db.collection(collectionMap[type]).findOne({ _id: new ObjectId(id) });
    if (!rule) return res.status(404).send('Rule not found');
    res.render(pageMap[type], { title: "Edit Rule", rule });
  } catch (err) {
    console.error(`Error loading ${type} rule:`, err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});


// ========== Edit POST Route (Shared) ==========

app.post('/rules/:type/edit/:id', authMiddleware, requirePermission("rules"), async (req, res) => {
  const { type, id } = req.params;
  const { name, pattern, content } = req.body;

  let updateData;
  if (type === 'regex') {
    if (!isValidRegex(pattern)) return res.status(400).send('Invalid regex pattern.');
    updateData = { [name]: pattern };
  } else if (type === 'topic') {
    updateData = { name, pattern };
  } else if (type === 'yara') {
    updateData = { name, content };
  } else {
    return res.status(400).send('Invalid rule type.');
  }

  let client;

  try {

    ({ client, db } = await connectToDB());

    await db.collection(`${type}_rules`).replaceOne({ _id: new ObjectId(id) }, updateData);

    if (type === 'topic') {
      // Notify gRPC service about topic rule update
      gRPC_client.TopicRuleEdited({ id }, () => {});   //Monitor service will handle the update from the database
    } else if (type === 'yara') { 
      // Notify gRPC service about YARA rule update
      gRPC_client.YaraRuleEdited({ id, rule: updateData }, () => {});
    } else if (type === 'regex') {
      // Notify gRPC service about regex rule update
      gRPC_client.RegexRuleEdited({ id }, () => {});
    }

    res.redirect(`/rules/${type}`);
  } catch (err) {
    console.error(`Error updating ${type} rule:`, err);
    res.status(500).send('Error updating rule');
  } finally {
    if (client) await client.close();
  }
});


// Secure file download endpoint to prevent path traversal attacks
app.get('/uploads/:file', authMiddleware, requirePermission("events"), (req, res) => {
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


app.get('/domains', authMiddleware, requirePermission("domains"), async (req, res) => {
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

app.post('/domains/delete/:id', authMiddleware, requirePermission("domains"), async (req, res) => {
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

app.post('/domains/add', authMiddleware, requirePermission("domains"), async (req, res) => {
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
    const token = jwt.sign({ id: user._id, username, permissions: user.permissions }, process.env.JWT_SECRET, { expiresIn: '1h' });
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

app.get('/user-management', authMiddleware, requirePermission("user_management"), async (req, res) => {
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


app.post('/add-user', authMiddleware, requirePermission("user_management"), async (req, res) => {
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

app.post('/update-password', authMiddleware, requirePermission("user_management"), async (req, res) => {
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

app.post('/delete-user', authMiddleware, requirePermission("user_management"), async (req, res) => {
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

app.get('/api/options', authMiddleware, requirePermission("events"), async (req, res) => {
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

app.get('/event/:id', authMiddleware, requirePermission("events"), async (req, res) => {
  const { id } = req.params;
  let client;
  try {
    ({ client, db } = await connectToDB());
    const events_collection = db.collection('events');
    const event = await events_collection.findOne({ _id: new ObjectId(id) });
    if (!event) return res.status(404).send('Event not found');

    // Get the Referer URL, or fallback to '/explore'
    let backUrl = req.get('Referer') || '/explore';
    const expectedPrefix = `https://${req.hostname}/explore`;
    if (!backUrl.startsWith(expectedPrefix)) {
      backUrl = '/explore';
    }

    res.render('event-detail', { title: "Event detail", event, backUrl });

  } catch (err) {
    console.error('Error fetching event:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.get('/stats', authMiddleware, requirePermission("statistics"), async (req, res) => {

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

app.get('/playground', authMiddleware, requirePermission("playground"), async (req, res) => {

  res.render('playground', { title: "Playground" });

});

app.post('/playground', authMiddleware, requirePermission("playground"), upload.single('fileUpload'), async (req, res) => {
  const { username, textContent } = req.body;
  const file = req.file;

  // Logging for debug/demo
  console.log('Received DLP submission:');
  console.log('Username:', username);
  console.log('Text Content:', textContent);

  let client;
  try {
    ({ client, db } = await connectToDB());
    const result = await db.collection('events').insertOne({
      "timestamp": new Date(), 
      "user": username, 
      "rational": "Conversation", 
      "content": textContent, 
      "site": "Playground"
    });

    gRPC_client.EventAdded({ id: result.insertedId }, () => {});

    if (file) {
      console.log('Uploaded file:', file.originalname);
      console.log('Stored at:', file.path);
      const result = await db.collection('events').insertOne({
        "timestamp": new Date(), 
        "user": username, 
        "rational": "Attached file", 
        "filename" : file.originalname,
        "filepath" : file.path, 
        "content_type": file.mimetype, 
        "site": "Playground"
      });
      gRPC_client.EventAdded({ id: result.insertedId }, () => {});
    }

    res.redirect('/playground');

  } catch (err) {
    console.error('Error adding regex rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

  
});

app.get('/sites', authMiddleware, requirePermission("sites"), async (req, res) => {

  let client;
  try {
    ({ client, db } = await connectToDB());
    const site_docs = await db.collection('sites').find().toArray();

    console.log('Loaded sites:', site_docs);

    res.render('sites', { title: "Sites", site_docs});

  } catch (err) {
    console.error('Error showing sites:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }  

});

const allPermissions = [
  "playground", "mitmterminal", "user_management", "rules",
  "events", "domains", "sites", "statistics", "alerts", "conversations"
];

// GET /manage-permissions
app.get('/manage-permissions', authMiddleware, requirePermission("user_management"), async (req, res) => {
  let client;
  try {
    ({ client, db } = await connectToDB());

    const { username } = req.query;
    const user = await db.collection('users').findOne({ username: username });
    if (!user) return res.status(404).send('User not found');

    res.render('manage-permissions', { title: "Manage permissions", user, allPermissions });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  } finally {
    if (client) await client.close();
  }  
});

// POST /update-permissions
app.post('/manage-permissions', authMiddleware, requirePermission("user_management"), async (req, res) => {
  let client;
  try {
    ({ client, db } = await connectToDB());
    const users = db.collection('users');

    const { username, permissions } = req.body;
    const updated = Array.isArray(permissions) ? permissions : [permissions];

    const result = await users.updateOne(
      { username },
      { $set: { permissions: updated } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).send('User not found');
    }

    res.redirect('/manage-permissions?username=' + encodeURIComponent(username));
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  } finally {
    if (client) await client.close();
  }

});


app.post('/add-event-to-topic-rules', authMiddleware, requirePermission("events"), requirePermission("conversations"), async (req, res) => {
  const { name, eventId } = req.body;
  if (!eventId) {
    return res.status(400).send('Event ID is required');
  }
  let client;
  try {
    ({ client, db } = await connectToDB());

    const event = await db.collection('events').findOne({ _id: new ObjectId(eventId) });

    if (!event) {
      return res.status(404).send('Event not found');
    }

    const result = await db.collection('topic_rules').insertOne({ name, pattern: event.content });

    gRPC_client.TopicRuleAdded({ id: result.insertedId }, () => {});

    res.redirect('/event/' + eventId);

  } catch (err) {

    console.error('Error adding event to topic rules:', err);
    res.status(500).send('Internal Server Error');

  } finally {

    if (client) await client.close();
    
  }

});

app.get('/alerts', authMiddleware, requirePermission("alerts"), async (req, res) => {
  try {
    res.render('alerts', { title: 'Alerts' });
  } catch (err) {
    console.error('Error rendering alerts:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Alert Destinations
app.get('/alerts/destinations', authMiddleware, requirePermission("alerts"), async (req, res) => {
  
  let client;

  try {
    ({ client, db } = await connectToDB());
    const alert_destinations = db.collection('alert-destinations');
    const destinations = await alert_destinations.find().toArray();

    res.render('alert-destinations', {
      title: 'Alert Destinations',
      destinations,
    });

  } catch (err) {
    console.error('Error rendering alert destinations:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/alerts/destinations', authMiddleware, requirePermission("alerts"), async (req, res) => {
  const {
    destinationName,
    destinationType,
    email,
    emailPassword,
    emailPasswordConfirm,
    smtpHost,
    smtpPort,
    syslogHost,
    syslogPort,
  } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const ipOrHostnameRegex = /^(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$/;

  const errors = [];

  for (let i = 0; i < destinationType.length; i++) {

    if (!destinationName[i]) {
      errors.push(`Row ${i + 1}: Name is required.`);
    }

    const type = destinationType[i];

    if (type === 'email') {
      if (!emailRegex.test(email[i])) {
        errors.push(`Row ${i + 1}: Invalid email address.`);
      }

      if (!emailPassword[i]) {
        errors.push(`Row ${i + 1}: Password is required.`);
      }

      if (emailPassword[i] !== emailPasswordConfirm[i]) {
        errors.push(`Row ${i + 1}: Passwords do not match.`);
      }

      if (!ipOrHostnameRegex.test(smtpHost[i])) {
        errors.push(`Row ${i + 1}: Invalid SMTP host.`);
      }

      const port = Number(smtpPort[i]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        errors.push(`Row ${i + 1}: Invalid SMTP port.`);
      }

    } else if (type === 'syslog') {
      if (!ipOrHostnameRegex.test(syslogHost[i])) {
        errors.push(`Row ${i + 1}: Invalid Syslog host.`);
      }

      const port = Number(syslogPort[i]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        errors.push(`Row ${i + 1}: Invalid Syslog port.`);
      }
    }
  }

  if (errors.length > 0) {
    // You can render the form again with the errors, or send JSON:
    return res.status(400).json({ success: false, errors });
  }

  // If all is good:

  let client;
  try {
    ({ client, db } = await connectToDB());
    const alert_destinations = db.collection('alert-destinations');

    await alert_destinations.deleteMany({});

    for (let i = 0; i < destinationType.length; i++) {
      destination = {
        name: destinationName[i],
        type: destinationType[i],
      }

      if (destinationType[i] === "email") {

        destination.email = email[i];
        destination.emailPassword = emailPassword[i];
        destination.smtpHost = smtpHost[i];
        destination.smtpPort = smtpPort[i];

      } else if (destinationType[i] === "syslog") {
        destination.syslogHost = syslogHost[i];
        destination.syslogPort = syslogPort[i];
      }

      await alert_destinations.insertOne(destination);

    }


  } catch (err) {
    console.error('Setting alerts destinations:', err);
    return res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

  res.redirect('/alerts/destinations');

});




// Alert Rules
app.get('/alerts/rules', authMiddleware, async (req, res) => {
  try {
    const mockRules = [
      {
        name: 'Failed Login Alert',
        regex: { rules: ['Regex1'], count: 3 },
        yara: { rules: ['Yara1'], count: 1 },
        topic: { rules: ['Topic1'], count: 2 },
        destinations: ['email', 'syslog']
      },
      {
        name: 'Suspicious Upload',
        regex: { rules: ['Regex2'], count: 1 },
        yara: { rules: ['Yara2'], count: 1 },
        topic: { rules: ['Topic2'], count: 1 },
        destinations: ['logs']
      }
    ];

    // Mock available rule options and destinations
    const options = {
      regexRules: ['Regex1', 'Regex2'],
      yaraRules: ['Yara1', 'Yara2'],
      topicRules: ['Topic1', 'Topic2'],
      destinations: ['email', 'syslog', 'logs']
    };

    res.render('alert-rules', { title: 'Alert Rules', rules: mockRules, options });
  } catch (err) {
    console.error('Error rendering alert rules:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Alert Logs
app.get('/alerts/logs', authMiddleware, async (req, res) => {
  try {
    // Replace with real log fetching logic
    const mockLogs = [
      { time: '2025-06-21 14:32', matched_rule: 'regex' },
      { time: '2025-06-21 15:01', matched_rule: 'yara' }
    ];
    res.render('alert-logs', { title: 'Alert Logs', logs: mockLogs });
  } catch (err) {
    console.error('Error rendering alert logs:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
