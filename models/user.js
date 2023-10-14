/** User class for message.ly */
const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require("../config");

/** User of the site. */

class User {
  constructor(username, password, first_name, last_name, phone) {
    (this.username = username),
      (this.password = password),
      (this.first_name = first_name),
      (this.last_name = last_name),
      (this.phone = phone);
  }
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `
    INSERT INTO users 
    (username, password, first_name, last_name, phone, join_at, last_login_at)
    VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp) RETURNING *
    `,
      [username, hashedPassword, first_name, last_name, phone]
    );

    const u = result.rows[0];

    return new User(u.username, u.password, u.first_name, u.last_name, u.phone);
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT username, password FROM users WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        return true;
      }
    } else {
      return false;
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users SET last_login_at=current_timestamp WHERE username=$1`,
      [username]
    );
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `
    SELECT username, first_name, last_name, phone, join_at, last_login_at
    FROM users
    WHERE username = $1
    `,
      [username]
    );
    const u = result.rows[0];
    if (!u) {
      throw new ExpressError("User not found", 404);
    }
    return u;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `
    SELECT m.id, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone
     FROM messages AS m
     LEFT JOIN users AS u
     ON u.username = m.to_username
     WHERE m.from_username = $1`,
      [username]
    );
    const messageData = result.rows;
    const data = messageData.map((m) => {
      return {
        id: m.id,
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
        to_user: {
          username: m.username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone,
        },
      };
    });
    return data;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `
    SELECT m.id, m.body, m.sent_at, m.read_at, u.username, u.first_name, u.last_name, u.phone
     FROM messages AS m
     LEFT JOIN users AS u
     ON u.username = m.from_username
     WHERE m.to_username = $1`,
      [username]
    );
    const messageData = result.rows;
    const data = messageData.map((m) => {
      return {
        id: m.id,
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
        from_user: {
          username: m.username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone,
        },
      };
    });
    return data;
  }
}

module.exports = { User };
