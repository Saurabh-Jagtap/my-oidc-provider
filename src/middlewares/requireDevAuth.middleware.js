export const requireDevAuth = (req, res, next) => {
  if (!req.session.developer) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
}
