const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");

const { ensureLoggedIn } = require("../middleware/auth");
const { User } = require("../models/user");

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/
router.get("/", ensureLoggedIn, async (req, res, next) => {
  try {
    const users = await User.all();
    return res.json(users);
  } catch (e) {
    return next(e);
  }
});

/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get("/:username", ensureLoggedIn, async (req, res, next) => {
  try {
    const user = await User.get(req.params.username);
    return res.json(user);
  } catch (e) {
    return next(e);
  }
});

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/to", ensureLoggedIn, async (req, res, next) => {
  try {
    const messagesTo = await User.messagesTo(req.params.username);
    return res.json(messagesTo);
  } catch (e) {
    return next(e);
  }
});

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/from", ensureLoggedIn, async (req, res, next) => {
  try {
    const messagesFrom = await User.messagesFrom(req.params.username);
    return res.json(messagesFrom);
  } catch (e) {
    return next(e);
  }
});

module.exports = router;
