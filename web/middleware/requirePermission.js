function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user?.permissions?.includes(permission)) {
      return res.status(403).render('unauthorized', { title: 'Unauthorized' });
    }
    next();
  };
}

module.exports = requirePermission;