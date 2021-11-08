const Users = require("../users/users-model");

function restricted(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ message: "You shall not pass!" });
  }
}

async function checkUsernameFree(req, res, next) {
  try {
    const { username } = req.body;
    const users = await Users.findBy({ username });

    if (users.length) {
      next({ status: 422, message: "Username taken" });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
}

async function checkUsernameExists(req, res, next) {
  try {
    const { username } = req.body;
    const users = await Users.findBy({ username });

    if (!users.length) {
      next({ status: 401, message: "Invalid credentials" });
    } else {
      req.user = users[0];
      next();
    }
  } catch (err) {
    next(err);
  }
}

function checkPasswordLength(req, res, next) {
  try {
    const { password } = req.body;
    if (!password || password.length < 3) {
      next({ status: 422, message: "Password must be longer than 3 chars" });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  checkUsernameFree,
  checkPasswordLength,
};
