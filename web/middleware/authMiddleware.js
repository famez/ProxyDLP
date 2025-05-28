const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).redirect('/login');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    res.locals.username = decoded.username;
    next();
  } catch {
    return res.status(401).redirect('/login');
  }
}

module.exports = authMiddleware;
