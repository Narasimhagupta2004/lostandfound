const jwt = require("jsonwebtoken");
const protect = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    return res.status(401).json({ msg: "No token, access denied" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // payload
    next();
  } catch {
    res.status(401).json({ msg: "Invalid token" });
  }
};

const authorize = (role) => {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ msg: "Forbidden" });
    }
    next();
  };
};

module.exports = { protect, authorize };
