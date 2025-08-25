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
const monitorPackageDefinition = protoLoader.loadSync(
  path.resolve(__dirname, 'monitor.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  }
);

const monitor_proto = grpc.loadPackageDefinition(monitorPackageDefinition).monitor;

// Load the protobuf
const proxyPackageDefinition = protoLoader.loadSync(
  path.resolve(__dirname, 'proxy.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  }
);

const proxy_proto = grpc.loadPackageDefinition(proxyPackageDefinition).proxy;


// Create the client
const gRPC_monitor_client = new monitor_proto.Monitor('monitor:50051', grpc.credentials.createInsecure());
const gRPC_proxy_client = new proxy_proto.Proxy('proxy:50051', grpc.credentials.createInsecure());


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
  const db = client.db('ProxyDLP');
  
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

app.get('/terminal/stats', authMiddleware, requirePermission("mitmterminal"), (req, res) => {

  gRPC_proxy_client.GetMitmStats({}, (err, response) => {
    if (err) {
      console.error("Error fetching stats:", err);
      return;
    }

    // response is a JS object with your fields

    res.json({
      active_connections: response.active_connections,
      peak_connections: response.peak_connections,
      rps: response.rps,
      mem: response.mem,
      dropped_flows: response.dropped_flows
    });

  });

});

app.get('/explore', authMiddleware, requirePermission("events"), async (req, res) => {

  const {
    start, end, user, site, rational,
    filename, filetype, content, leak, order = 'desc',
    playground, source_ip, conversation_id
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
  if (source_ip) query.source_ip = { $regex: new RegExp(source_ip, 'i') };

  if (conversation_id) query.conversation_id = conversation_id;

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

      const pipeline = [
        { $match: query },
        {
          $addFields: {
            leakRegexArray: { $objectToArray: "$leak.regex" },
            leakNerArray: { $objectToArray: "$leak.ner" }
          }
        },
        {
          $match: {
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

      res.render('explore', {
        title: 'Explore',
        events,
        filters: req.query
      });
    } else {
      const events = await event_collection.find(query).sort(sort).skip(skip).limit(limit).toArray();

      res.render('explore', {
        title: 'Explore',
        events,
        filters: req.query
      });
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
    gRPC_monitor_client.RegexRuleAdded({ id: result.insertedId }, () => {});
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
    gRPC_monitor_client.TopicRuleAdded({ id: result.insertedId }, () => {});
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
  const result = gRPC_monitor_client.YaraRuleAdded({ name: name, content: content }, (err, response) => {
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

    const alert_rules = db.collection('alert-rules');
    const ruleId = new ObjectId(id);

    // Sanity check to avoid deletion of rules being used by alerts
    const query = {};
    query[`${type}.rules`] = ruleId;

    const alertRulesUsingRules = await alert_rules.find(query).toArray();

      if (alertRulesUsingRules.length > 0) {
        const blockingRules = alertRulesUsingRules.map(rule => rule.name || rule._id.toString());
        console.error(`Cannot delete ${type} rule in use by alert rules: ${blockingRules.join(', ')}`);
        return res.status(409).send(`Cannot delete ${type} rule in use by alert rules: ${blockingRules.join(', ')}`);
      }

    if (type === 'topic') {
      // Notify gRPC service about topic rule deletion
      gRPC_monitor_client.TopicRuleRemoved({ id }, () => {});   //Monitor service will handle the deletion from the database
    } else if (type === 'yara') { 
      // Notify gRPC service about YARA rule deletion
      await db.collection(`${type}_rules`).deleteOne({ _id: new ObjectId(id) });
      gRPC_monitor_client.YaraRuleRemoved({ id }, () => {});
    } else if (type === 'regex') {
      // Notify gRPC service about regex rule deletion
      await db.collection(`${type}_rules`).deleteOne({ _id: new ObjectId(id) });
      gRPC_monitor_client.RegexRuleRemoved({ id }, () => {});
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
      gRPC_monitor_client.TopicRuleEdited({ id }, () => {});   //Monitor service will handle the update from the database
    } else if (type === 'yara') { 
      // Notify gRPC service about YARA rule update
      gRPC_monitor_client.YaraRuleEdited({ id: {id}, rule: updateData }, () => {});
    } else if (type === 'regex') {
      // Notify gRPC service about regex rule update
      gRPC_monitor_client.RegexRuleEdited({ id }, () => {});
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

    const settings = await db.collection("domain-settings").findOne();
    const checkDomain = settings ? settings.check_domain : false;
    const allowAnonymous = settings ? settings.allow_anonymous : false;

    res.render('domains', { title: "Domains", domains, checkDomain, allowAnonymous });
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
      return res.status(400).render('error', { 
        title: 'Invalid Password', 
        message: 'Password must be at least 12 characters long and include uppercase, lowercase, number, and special character.' 
      });
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

  const allowedFields = ['user', 'site', 'rational', 'filename', 'content_type', 'source_ip'];
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

      // Backend data example
      wordRelevancyStats = await db.collection('events').aggregate([
        { $unwind: '$tfidf_top_words' },
        { $group: { _id: '$tfidf_top_words.word', count: { $sum: 1 } } },
        { $project: { word: '$_id', count: 1, _id: 0 } },  // rename _id to word, remove _id
        { $sort: { count: -1 } },
        { $limit: 15 }
      ]).toArray();


      console.log("Word stats:" + JSON.stringify(wordRelevancyStats, null, 2))

      fileExtensionsStats = await db.collection('events').aggregate([
        // Filter only events with a filename field (uploaded files)
        { $match: { filename: { $exists: true, $ne: null } } },

        // Extract file extension from filename
        {
          $addFields: {
            extension: {
              $toLower: {
                $let: {
                  vars: {
                    parts: { $split: ["$filename", "."] }
                  },
                  in: {
                    $cond: [
                      { $gt: [{ $size: "$$parts" }, 1] },
                      { $concat: [".", { $arrayElemAt: ["$$parts", { $subtract: [{ $size: "$$parts" }, 1] }] }] },
                      ""  // no extension found
                    ]
                  }
                }
              }
            }
          }
        },

        // Group by extension and count
        {
          $group: {
            _id: "$extension",
            count: { $sum: 1 }
          }
        },

        // Sort descending
        { $sort: { count: -1 } },

        // Limit if you want top N extensions, e.g., 10
        { $limit: 15 },

        // Project to rename _id to extension
        {
          $project: {
            extension: "$_id",
            count: 1,
            _id: 0
          }
        }
      ]).toArray();

    console.log("File extensions stats:", fileExtensionsStats);    
    await client.close();

    res.render('stats', {title: "Statistics", 
      riskyEvents,
      topicStats,
      toolUsage,
      userStats,
      regexLabelStats,
      regexHeavyEvents,
      topMatchedWords,
      wordRelevancyStats,
      fileExtensionsStats
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
      "site": "Playground",
      "source_ip": req.ip,
    });

    gRPC_monitor_client.EventAdded({ id: result.insertedId }, () => {});

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
      gRPC_monitor_client.EventAdded({ id: result.insertedId }, () => {});
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

    const site_settings = await db.collection("site-settings").findOne();
    const rejectTraffic = site_settings ? site_settings.rejectTraffic : false;

    console.log("rejectTraffic: ", rejectTraffic)


    res.render('sites', { title: "Sites", site_docs, rejectTraffic});

  } catch (err) {
    console.error('Error showing sites:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }  

});


app.post('/sites/reject-traffic', authMiddleware, requirePermission("sites"), async (req, res) => {


  let client;
  try {

    ({ client, db } = await connectToDB());

    const site_settings = await db.collection('site-settings').find().toArray();

    const { reject_traffic } = req.body;

    if (typeof reject_traffic !== "boolean") {
      return res.status(400).send("reject_traffic must be a boolean");
    }

    const result = await db.collection('site-settings').updateOne(
      {}, // filter - empty means update the first document found
      { $set: { rejectTraffic: reject_traffic } },
      { upsert: true }
    );

    if (result.modifiedCount === 0 && result.upsertedCount === 0) {
      return res.status(500).send("Failed to update site settings");
    }

    gRPC_proxy_client.SiteRejectEnabled({ enabled: reject_traffic }, () => {});


    res.sendStatus(200);

  } catch (err) {
    console.error('Error setting sites config:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }  

});

app.post('/sites/toggle-monitoring', authMiddleware, requirePermission("sites"), async (req, res) => {

  let client;
  try {
    ({ client, db } = await connectToDB());

    const { site_id, enabled } = req.body;

    if (!site_id || typeof enabled !== "boolean") {
      return res.status(400).send("site_id and enabled (boolean) are required");
    }

    // Update the site document
    const result = await db.collection('sites').updateOne(
      { _id: new ObjectId(site_id) }, // filter by site_id
      { $set: { enabled } },
      { upsert: false }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).send("Site not found or already in desired state");
    }

    gRPC_proxy_client.SiteMonitoringToggled({ id: site_id, enabled }, () => {});

    res.sendStatus(200);

  } catch (err) {
    console.error('Error toggling site monitoring:', err);
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


    return res.render('success', { 
        title: 'Permissions changed', 
        message: 'Permissions have been properly changed' 
      });

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

    gRPC_monitor_client.TopicRuleAdded({ id: result.insertedId }, () => {});

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

    const localLogsEnabled = await alert_destinations.findOne({
      type: 'local_logs',
      enabled: true
    });

    res.render('alert-destinations', {
      title: 'Alert Destinations',
      destinations,
      localLogsEnabled
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
    destinationId = [],
    destinationName,
    destinationType,
    email,
    emailPassword,
    emailPasswordConfirm,
    smtpHost,
    smtpPort,
    syslogHost,
    syslogPort,
    recipientEmail,
  } = req.body;
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const ipOrHostnameRegex = /^(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$/;

  const errors = [];

  // Validation
  if (Array.isArray(destinationType)) {
    for (let i = 0; i < destinationType.length; i++) {
      if (!destinationName[i]) {
        errors.push(`Row ${i + 1}: Name is required.`);
      }

      const type = destinationType[i];

      if (type !== "local_logs" && destinationName[i] === "Local logs") {
        errors.push(`Row ${i + 1}: Invalid name 'Local logs'. This name is reserved.`);
      }

      if (type === 'email') {
        if (!emailRegex.test(email[i])) {
          errors.push(`Row ${i + 1}: Invalid email address.`);
        }

        if (!emailRegex.test(recipientEmail[i])) {
          errors.push(`Row ${i + 1}: Invalid recipient email.`);
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
      return res.status(400).json({ success: false, errors });
    }
  }

  let client;

  try {
    ({ client, db } = await connectToDB());
    const alert_destinations = db.collection('alert-destinations');
    const alert_rules = db.collection('alert-rules');


    const existing = await alert_destinations.find({ type: { $ne: 'local_logs' } }).toArray();
    const existingIds = existing.map(dest => String(dest._id));

    const updatedIds = [];

    if (Array.isArray(destinationType)) {
      for (let i = 0; i < destinationType.length; i++) {
        const type = destinationType[i];
        const id = destinationId[i];
        const base = {
          name: destinationName[i],
          type
        };

        if (type === 'email') {
          Object.assign(base, {
            email: email[i],
            emailPassword: emailPassword[i],
            smtpHost: smtpHost[i],
            smtpPort: smtpPort[i],
            recipientEmail: recipientEmail[i]
          });
        } else if (type === 'syslog') {
          Object.assign(base, {
            syslogHost: syslogHost[i],
            syslogPort: syslogPort[i]
          });
        }

        if (id && ObjectId.isValid(id)) {
          await alert_destinations.updateOne(
            { _id: new ObjectId(id) },
            { $set: base }
          );
          updatedIds.push(id);
        } else {
          await alert_destinations.insertOne(base);
        }
      }
    }

    // Remove any documents not in the submitted form (except local_logs)
    const toDelete = existingIds.filter(id => !updatedIds.includes(id));

    if (toDelete.length > 0) {
      const toDeleteObjectIds = toDelete.map(id => new ObjectId(id));

      // Check if any of the destinations are used in alert_rules
      const rulesUsingDestinations = await alert_rules.find({
        destinations: { $in: toDeleteObjectIds }
      }).toArray();

      if (rulesUsingDestinations.length > 0) {
        const blockingRules = rulesUsingDestinations.map(rule => rule.name || rule._id.toString());
        console.error(`Cannot delete destinations in use by alert rules: ${blockingRules.join(', ')}`);
        return res.status(409).send(`Cannot delete destinations in use by alert rules: ${blockingRules.join(', ')}`);
      }

      // Safe to delete
      await alert_destinations.deleteMany({
        _id: { $in: toDeleteObjectIds }
      });
    }



    res.redirect('/alerts/destinations');

  } catch (err) {
    console.error('Error saving alert destinations:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});


// Alert Rules
app.get('/alerts/rules', authMiddleware, requirePermission("alerts"), async (req, res) => {
  
  let client;
  try {
    
    //Get all the yara, regex and topic rules + available destinations.

    
    ({ client, db } = await connectToDB());

    const rules = await db.collection('alert-rules').aggregate([
      // Lookup regex rule details
      {
        $lookup: {
          from: 'regex_rules',
          localField: 'regex.rules',
          foreignField: '_id',
          as: 'regexResolved'
        }
      },
      // Lookup yara rule details
      {
        $lookup: {
          from: 'yara_rules',
          localField: 'yara.rules',
          foreignField: '_id',
          as: 'yaraResolved'
        }
      },
      // Lookup topic rule details
      {
        $lookup: {
          from: 'topic_rules',
          localField: 'topic.rules',
          foreignField: '_id',
          as: 'topicResolved'
        }
      },
      // Resolve destinations by matching name
      {
        $lookup: {
          from: 'alert-destinations',
          localField: 'destinations',
          foreignField: '_id',
          as: 'destinationResolved'
        }
      },
      
      // Optional: remap result shape
      {
        $project: {
          _id: 1,
          name: 1,
          regex: {
            count: '$regex.count',
            rules: '$regexResolved'
          },
          yara: {
            count: '$yara.count',
            rules: '$yaraResolved'
          },
          topic: {
            count: '$topic.count',
            rules: '$topicResolved'
          },
          destinations: '$destinationResolved'
        }
      }
    ]).toArray();

    
    const yara_rules = await db.collection('yara_rules').find().toArray();
    const regex_rules = await db.collection('regex_rules').find().toArray();
    const topic_rules = await db.collection('topic_rules').find().toArray();
    const alert_dests = await db.collection('alert-destinations').find().toArray();

    const options = {
      regexRules: regex_rules,
      yaraRules: yara_rules,
      topicRules: topic_rules,
      destinations: alert_dests
    };

    res.render('alert-rules', { title: 'Alert Rules', rules, options });
    
  } catch (err) {
    console.error('Error rendering alert rules:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

});


app.post('/alerts/rules', authMiddleware, requirePermission("alerts"), async (req, res) => {

  let client;
  try {
    const {
      name,
      regexRules,
      regexCount,
      yaraRules,
      yaraCount,
      topicRules,
      topicCount,
      destinations
    } = req.body;

    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ error: 'Name is required and cannot be empty.' });
    }

    const parseField = val => Array.isArray(val) ? val : val ? [val] : [];

    const parsedDestinations = parseField(destinations);

    if (parsedDestinations.length === 0) {
      return res.status(400).send('At least one destination must be selected.');
    }

    const doc = {
      name,
      regex: {
        rules: parseField(regexRules).map(id => new ObjectId(id)),
        count: parseInt(regexCount) || 1
      },
      yara: {
        rules: parseField(yaraRules).map(id => new ObjectId(id)),
        count: parseInt(yaraCount) || 1
      },
      topic: {
        rules: parseField(topicRules).map(id => new ObjectId(id)),
        count: parseInt(topicCount) || 1
      },
      destinations: parsedDestinations.map(id => new ObjectId(id))
    };

    ({ client, db } = await connectToDB());

    await db.collection('alert-rules').insertOne(doc);

    res.redirect('/alerts/rules/');

  } catch (err) {
    console.error('Error inserting alert rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }

});

app.get('/alerts/rules/:id/edit', authMiddleware, requirePermission("alerts"), async (req, res) => {
  let client;
  try {
    const { id } = req.params;
    ({ client, db } = await connectToDB());

    const rule = await db.collection('alert-rules').findOne({ _id: new ObjectId(id) });
    if (!rule) return res.status(404).send('Rule not found');

    const [regexRules, yaraRules, topicRules, destinations] = await Promise.all([
      db.collection('regex_rules').find().toArray(),
      db.collection('yara_rules').find().toArray(),
      db.collection('topic_rules').find().toArray(),
      db.collection('alert-destinations').find().toArray()
    ]);

    res.render('alert-rules-edit', {
      title: 'Edit Rule',
      rule,
      options: { regexRules, yaraRules, topicRules, destinations }
    });

  } catch (err) {
    console.error('Error rendering edit page:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/alerts/rules/:id/edit', authMiddleware, requirePermission("alerts"), async (req, res) => {
  let client;
  try {
    const { id } = req.params;
    const {
      name, regexRules, regexCount, yaraRules, /*yaraCount,*/
      topicRules, /*topicCount,*/ destinations
    } = req.body;

    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ error: 'Name is required and cannot be empty.' });
    }


    const parseField = val => Array.isArray(val) ? val : val ? [val] : [];

    const parsedDestinations = parseField(destinations);

    if (parsedDestinations.length === 0) {
      return res.status(400).send('At least one destination must be selected.');
    }

    const updateDoc = {
      name,
      regex: {
        rules: parseField(regexRules).map(r => new ObjectId(r)),
        count: parseInt(regexCount) || 1
      },
      yara: {
        rules: parseField(yaraRules).map(r => new ObjectId(r)),
        count: parseInt(/*yaraCount*/1) || 1
      },
      topic: {
        rules: parseField(topicRules).map(r => new ObjectId(r)),
        count: parseInt(/*topicCount*/1) || 1
      },
      destinations: parseField(destinations).map(r => new ObjectId(r))
    };

    ({ client, db } = await connectToDB());
    await db.collection('alert-rules').updateOne(
      { _id: new ObjectId(id) },
      { $set: updateDoc }
    );

    res.redirect('/alerts/rules');

  } catch (err) {
    console.error('Error updating rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});


app.post('/alerts/rules/:id/delete', authMiddleware, requirePermission("alerts"), async (req, res) => {
  let client;
  try {
    const { id } = req.params;
    ({ client, db } = await connectToDB());

    await db.collection('alert-rules').deleteOne({ _id: new ObjectId(id) });

    res.redirect('/alerts/rules');

  } catch (err) {
    console.error('Error deleting rule:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});



// Alert Logs
app.get('/alerts/logs', authMiddleware, requirePermission("alerts"), async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const skip = (page - 1) * limit;

  let client;
  try {
    ({ client, db } = await connectToDB());

    const totalLogs = await db.collection('alert-logs').countDocuments();
    const logs = await db.collection('alert-logs').aggregate([
      { $sort: { timestamp: -1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $project: {
          timestamp: 1,
          leak: 1,
          alert_rule: 1
        }
      }
    ]).toArray();

    const formattedLogs = logs.map(log => {
      const ts = new Date(log.timestamp.$date || log.timestamp).toISOString().replace('T', ' ').substring(0, 16);
      const alert_rule = log.alert_rule || 'Unknown Rule';

      const yaraNames = Array.isArray(log.leak?.yara) ? log.leak.yara.map(y => y.name).join(', ') : '';
      const regexEntries = log.leak?.regex ? Object.entries(log.leak.regex).map(([k, v]) => `${k}: ${v}`).join('; ') : '';
      const topicNames = Array.isArray(log.leak?.topic) ? log.leak.topic.map(t => t.name).join(', ') : '';

      return { time: ts, alert_rule, yara: yaraNames, regex: regexEntries, topic: topicNames };
    });

    const localDest = await db.collection('alert-destinations').findOne({ type: 'local_logs' });
    const rotationLimit = localDest?.rotationLimit || 500;

    res.render('alert-logs', {
      title: 'Alert Logs',
      logs: formattedLogs,
      pagination: {
        current: page,
        totalPages: Math.ceil(totalLogs / limit),
        limit
      }, rotationLimit
    });

  } catch (err) {
    console.error('Error rendering alert logs:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/alerts/logs/rotation', authMiddleware, requirePermission("alerts"), async (req, res) => {
  const maxLogs = parseInt(req.body.maxLogs) || 500;

  let client;
  try {
    ({ client, db } = await connectToDB());

    // Update the rotation limit
    await db.collection('alert-destinations').updateOne(
      { type: 'local_logs' },
      { $set: { rotationLimit: maxLogs } }
    );

    res.redirect('/alerts/logs');
  } catch (err) {
    console.error('Error updating rotation limit:', err);
    res.status(500).send('Internal Server Error');
  } finally {
    if (client) await client.close();
  }
});

app.post('/domains/check-domain', authMiddleware, requirePermission("domains"), async (req, res) => {
  let client;
  try {
    ({ client, db } = await connectToDB());

    const { check_domain } = req.body;
    if (typeof check_domain !== 'boolean') {
      return res.status(400).json({ error: 'Invalid check_domain value' });
    }

    await db.collection("domain-settings").updateOne({}, { $set: { check_domain } });

    res.json({ success: true, check_domain });
  } catch (err) {
    console.error('Error updating check_domain:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    if (client) await client.close();
  }
});

app.post('/domains/allow-anonymous', authMiddleware, requirePermission("domains"), async (req, res) => {
  let client;
  try {
    const { client: dbClient, db } = await connectToDB();
    client = dbClient;

    const { allow_anonymous } = req.body;
    if (typeof allow_anonymous !== 'boolean') {
      return res.status(400).json({ error: 'Invalid allow_anonymous value' });
    }

    await db.collection("domain-settings").updateOne(
      {},
      { $set: { allow_anonymous } },
    );

    res.json({ success: true, allow_anonymous });
  } catch (err) {
    console.error('Error updating allow_anonymous:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    if (client) await client.close();
  }
});


app.post('/generate-pac', authMiddleware, requirePermission("sites"), async (req, res) => {

  let client;

  try {
    ({ client, db } = await connectToDB());
    const site_docs = await db.collection('sites').find().toArray();

    // Flatten all URL entries
    const rawUrls = site_docs.flatMap(site => site.urls || []);
    const cleanedUrls = rawUrls.map(url => url.trim()).filter(Boolean);

    const proxyInput = req.body.proxy?.trim();

    if (!proxyInput) {
      return res.status(400).send("Proxy address is required.");
    }

    // Match host:port (IPv4 or DNS)
    const proxyPattern = /^([a-zA-Z0-9.-]+):(\d{1,5})$/;
    const match = proxyInput.match(proxyPattern);

    if (!match) {
      return res.status(400).render('error', { 
        title: 'Invalid Proxy', 
        message: 'Invalid proxy format. Use host:port (e.g., 192.168.0.1:8080 or proxy.example.com:3128).' 
      });
    }

    const host = match[1];
    const port = parseInt(match[2], 10);

    if (port < 1 || port > 65535) {
      return res.status(400).render('error', { 
        title: 'Invalid Proxy', 
        message: 'Invalid port number. Must be between 1 and 65535.' 
      });
    }

    // Validate host (either valid IP or DNS name)
    const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    let validHost = false;

    if (isIPv4) {
      const octets = host.split('.').map(Number);
      validHost = octets.every(o => o >= 0 && o <= 255);
    } else {
      // DNS: labels (a-z0-9), may have hyphens, dots between labels
      validHost = /^[a-zA-Z0-9-]{1,63}(\.[a-zA-Z0-9-]{1,63})+$/.test(host);
    }

    if (!validHost) {
      return res.status(400).render('error', { 
        title: 'Invalid Proxy', 
        message: 'Invalid host. Must be a valid IPv4 address or DNS name.' 
      });
    }

    // Safe to use
    const proxy = `${host}:${port}`;

    // Generate PAC file content
    // Build PAC rules using host-based matching
    
    // Extract unique domains only (drop any path after slash)
    const domains = [...new Set(
      cleanedUrls.map(url => url.split('/')[0].toLowerCase())
    )];

    const pacConditions = domains.map(domain => {
      return `        dnsDomainIs(host, "${domain}")`;
    }).join(' ||\n');

    const pacContent = `
    function FindProxyForURL(url, host) {
        // Define domains to proxy
        if (
    ${pacConditions}
        ) {
            return "PROXY ${proxy}";
        }

        // All other traffic bypasses proxy
        return "DIRECT";
    }
    `.trim();

    res.setHeader('Content-Type', 'application/x-ns-proxy-autoconfig');
    res.setHeader('Content-Disposition', 'attachment; filename="proxy.pac"');
    res.send(pacContent);

  } catch (err) {
    console.error('Error generating PAC file:', err);
    res.status(500).send('Failed to generate PAC file.');
  } finally {
    if (client) await client.close();
  }
});



app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
