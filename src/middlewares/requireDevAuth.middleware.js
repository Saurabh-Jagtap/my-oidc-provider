export const requireDevAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }

  if (req.session.user.role !== "developer") {
    return res.redirect("/become-dev.html");
  }

  next();
}
