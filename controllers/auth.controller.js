require("express-async-errors");
const createError = require("http-errors");
var bcrypt = require("bcryptjs");

const db = require("../services/db");

const jwt = require("jsonwebtoken");

class AuthController {
  static user = async (req, res, next) => {
    try {
      if (req.session.user === undefined) {
        res.status(401).json({
          message: "Unauthorized!",
        });
        return;
      }

      const id = req.session.user.id;

      const query =
        "SELECT id, account_type, name, email FROM users WHERE id=?";
      const values = [id];

      const result = await db.query(query, values);

      res.status(200).json(result);
    } catch (e) {
      next(createError(500, e.message));
    }
  };

  static users = async (req, res, next) => {
    try {
      // Route Guard - if wala ni log in ang user, then dili niya makita ni na function response...
      if (req.session.user === undefined) {
        res.status(401).json({
          message: "Unauthorized!",
        });
        return;
      }

      const userQuery = "SELECT * FROM users";

      const result = await db.query(userQuery);

      res.status(200).json(result);
    } catch (e) {
      next(createError(500, e.message));
    }
  };

  static register = async (req, res, next) => {
    try {
      // Payload Body - atong kuhaon ang payload gikan sa frontend pinaagi sa req.body aron naa tay access sa Form Inputs
      const { name, email, password } = req.body;

      // Form Validation - dapat i handle nato na naa gud value ang Name, Email ug Password
      if (!name || name.trim() === "") {
        return res.status(400).json({
          message: "Name is required!",
        });
      }

      if (!email || email.trim() === "") {
        return res.status(400).json({
          message: "Email is required!",
        });
      }

      if (!password || password.trim() === "") {
        return res.status(400).json({
          message: "Password is required!",
        });
      }

      // BCRYPT -  encrypt ang password aron secure account bisag masave sa database...
      const salt = await bcrypt.genSalt();
      const hashPassword = await bcrypt.hash(password, salt);

      // Use parameterized query to prevent SQL injection (Security aron di mahack ang sql query)...
      const query =
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
      const values = [name, email, hashPassword];

      const result = await db.query(query, values);

      // icheck if naa nabay affectedRows, if naa na meaning nasod na siya sa atong database...
      if (result.affectedRows) {
        return res.status(200).json({
          message: "Registered Successfully!",
        });
      } else {
        return res.status(500).json({
          message: "Failed to register user!",
        });
      }
    } catch (e) {
      next(createError(500, e.message));
    }
  };

  static login = async (req, res, next) => {
    try {
      const { email, password } = req.body;

      if (!email || email.trim() === "") {
        return res.status(400).json({
          message: "Email is required!",
        });
      }

      if (!password || password.trim() === "") {
        return res.status(400).json({
          message: "Password is required!",
        });
      }

      // icheck sa nato if naa ba ang user sa database using email...
      const foundUserQuery =
        "SELECT id, email, password FROM `users` WHERE email=?";
      const foundUserValue = [email];

      const foundUserResult = await db.query(foundUserQuery, foundUserValue);

      // if wala ang user sa database, mao ni ang error madawat sa frontend...
      if (foundUserResult.length === 0) {
        return res.status(400).json({
          message: "Account not found, create account first.",
        });
      }

      // kung naa ang user sa database, atong ispread as variable ang user_id and user_hashed_password...
      const userId = foundUserResult[0].id;
      const userHashPassword = foundUserResult[0].password;

      // atong gamiton ang bcryptjs aron ma decrypt ang encrypted na password sa user sa database...
      const matchedPassword = await bcrypt.compare(password, userHashPassword);

      // kung dili match ang giinput na password mag release tag error sa frontend...
      if (!matchedPassword) {
        return res.status(400).json({
          message: "Password is incorrect!",
        });
      }

      // kung success na tanan ang pag login sa user, usa nata maghimo ug session or token para sa authenticated user na ni logged in

      // const token = jwt.sign(
      //   {
      //     userId,
      //     email,
      //   },
      //   "secret"
      // );

      req.session.user = { id: userId };

      await req.session.save();

      res.status(200).json({
        message: "Logged in successfully.",
        user: {
          email,
          userId,
        },
      });
    } catch (e) {
      next(createError(500, e.message));
    }
  };
}

module.exports = AuthController;
