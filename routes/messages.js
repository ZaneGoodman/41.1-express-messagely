const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");

const { ensureLoggedIn } = require("../middleware/auth");

const Message = require("../models/message");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/:id", ensureLoggedIn, async (req, res, next) => {
  try {
    const { id } = req.params;
    const msg = await Message.get(id);
    if (
      req.user.username !== msg.to_user ||
      req.user.username !== msg.from_user
    ) {
      throw new ExpressError("Not authorized to see this message", 404);
    }
    return res.json(msg);
  } catch (e) {
    return next(e);
  }
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", ensureLoggedIn, async (req, res, next) => {
  try {
    const { from_username, to_username, body } = req.body;
    const newMsg = await Message.create({ from_username, to_username, body });
    return res.json({ message: newMsg });
  } catch (e) {
    return next(e);
  }
});
/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", ensureLoggedIn, async (req, res, next) => {
  try {
    const readData = await Message.markRead(req.params.id);
    return res.json(readData);
  } catch (e) {
    return next(e);
  }
});
module.exports = router;
