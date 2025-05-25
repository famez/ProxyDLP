var regex_rules = 
[
  {"Credit card number": "\\b(?:\\d[ -]*?){13,16}\\b"},
  {"Public IP addresses": "\\b(?!(10|127|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168))(?:(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)\\b"},
  {"IBAN": "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\\b"},
  {"Phone number": "\\+?\\d{1,4}\\d{9,10}"},
  {"Email Address": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}"},
  {"Confidential label": "Contoso S.A - Confidential"}
]

var cos_sim_rules = 
[
    {"User manual": "User manual for engineering = YES"},
    {"Specification": "Specification of requirements = YES"},
    {"Assembly Manual": "Assembly instruction = YES"}
]

db = db.getSiblingDB('proxyGPT'); // Creates database 'proxyGPT'

db.createCollection('events');

db.createCollection('regex_rules');
db.createCollection('cos_sim_rules');

db.createCollection('domains');

db.regex_rules.insertMany(regex_rules);
db.cos_sim_rules.insertMany(cos_sim_rules);