var regex_rules = 
[
  {"Credit card number": "\\b(?:\\d[ -]*?){13,16}\\b"},
  {"Public IP addresses": "\\b(?!(10|127|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168))(?:(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\b"},
  {"IBAN": "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\\b"},
  {"Phone number": "\\+?\\d{1,4}\\d{9,10}"},
  {"Email Address": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}"},
  {"Confidential label": "Contoso S.A - Confidential"}
]

db = db.getSiblingDB('ProxyDLP'); // Creates database 'ProxyDLP'

db.createCollection('users');

db.createCollection('events');
db.createCollection('regex_rules');
db.createCollection('topic_rules');
db.createCollection('yara_rules');
db.createCollection('domains');
db.createCollection('faiss_id_counters');
db.createCollection('sites');


db.topic_rules.createIndex({ "name": 1 }, { unique: true })
db.yara_rules.createIndex({ "name": 1 }, { unique: true })
db.sites.createIndex({ "name": 1 }, { unique: true })

//Insert default admin user

db.users.insertOne({username: "admin", password: "$2a$10$3lKl1v9l8Fe8PtAOCAEiaeXW.fTaCpKyCWJcuD1zELyFi2OZKIZBe",
  permissions: ["playground", "mitmterminal", "user_management", "rules","events", "domains", "sites", "statistics", "alerts", "conversations"],
}) //Hashed password for "admin" password

db.regex_rules.insertMany(regex_rules);
