// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require("express").Router();
const {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
} = require("./auth-middleware");
const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");

router.post(
  "/register",
  checkPasswordLength,
  checkUsernameFree,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const hash = bcrypt.hashSync(password, 10);
      const newUser = { username, password: hash };
      const user = await Users.add(newUser);
      res.status(201).json({ username: user.username, user_id: user.user_id });
    } catch (error) {
      next(error);
    }
  }
);
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { password } = req.body;
    if (bcrypt.compareSync(password, req.user.password)) {
      req.session.user = req.user;
      next({ status: 200, message: `Welcome ${req.session.user.username}` });
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
  } catch (error) {
    next(error);
  }
});
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", (req, res, next) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        res.json({ message: "Something happened, try again" });
      } else {
        res.status(200).json({ message: "logged out" });
      }
    });
  } else {
    res.status(200).json({ message: "no session" });
  }
});
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
