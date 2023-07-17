const { toTitleCase, validateEmail } = require("../config/function");
const bcrypt = require("bcryptjs");
const userModel = require("../models/users");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/keys");

const { logActivity } = require("../logs/logger");

// Commonly used passwords blacklist
const commonPasswords = [
  "password",
  "123456",
  "qwerty",
  "12345678",
  "111111",
  "dragon",
  "pooja123",
  // Add more common passwords to this list...
];

class Auth {
  async isAdmin(req, res) {
    let { loggedInUserId } = req.body;
    try {
      let loggedInUserRole = await userModel.findById(loggedInUserId);
      res.json({ role: loggedInUserRole.userRole });
    } catch {
      res.status(404);
    }
  }

  async allUser(req, res) {
    try {
      let allUser = await userModel.find({});
      res.json({ users: allUser });
    } catch {
      res.status(404);
    }
    logActivity("find all user");
  }

  /* User Registration/Signup controller  */
  async postSignup(req, res) {
    let { name, email, password, cPassword } = req.body;
    let error = {};

    if (!name || !email || !password || !cPassword) {
      error = {
        ...error,
        name: "Filed must not be empty",
        email: "Filed must not be empty",
        password: "Filed must not be empty",
        cPassword: "Filed must not be empty",
      };
      return res.json({ error });
    }

    if (name.length < 3 || name.length > 25) {
      error = { ...error, name: "Name must be 3-25 charecter" };
      return res.json({ error });
    }

    if (password.length < 8 || password.length > 255) {
      error = {
        ...error,
        password: "Password must be between 8 and 255 characters",
      };
      return res.json({ error });
    }

    // Check if the password contains personal information
    if (
      password.toLowerCase().includes(name.toLowerCase()) ||
      password.toLowerCase().includes(email.toLowerCase())
    ) {
      error = {
        ...error,
        password:
          "Password should not include personal information such as your name or email",
        name: "",
        email: "",
      };
      return res.json({ error });
    }

    // Password complexity validation
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      error = {
        ...error,
        password:
          "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character",
      };
      return res.json({ error });
    }

    // Check if the password is a common password
    if (commonPasswords.includes(password.toLowerCase())) {
      error = {
        ...error,
        password: "This password is too common. Please choose a stronger one.",
        name: "",
        email: "",
      };
      return res.json({ error });
    }

    if (validateEmail(email)) {
      name = toTitleCase(name);
      if ((password.length > 255) | (password.length < 8)) {
        error = {
          ...error,
          password: "Password must be 8 charecter",
          name: "",
          email: "",
        };
        return res.json({ error });
      }
      // If Email & Number exists in Database then:

      try {
        password = bcrypt.hashSync(password, 10);
        const data = await userModel.findOne({ email: email });
        if (data) {
          error = {
            ...error,
            password: "",
            name: "",
            email: "Email already exists",
          };
          return res.json({ error });
        } else {
          let newUser = new userModel({
            name,
            email,
            password,
            // ========= Here role 1 for admin signup role 0 for customer signup =========
            userRole: 1, // Field Name change to userRole from role
          });
          newUser
            .save()
            .then((data) => {
              return res.json({
                success: "Account create successfully. Please login",
              });
            })
            .catch((err) => {
              console.log(err);
            });
        }
      } catch (err) {
        console.log(err);
      }
    } else {
      error = {
        ...error,
        password: "",
        name: "",
        email: "Email is not valid",
      };
      return res.json({ error });
    }

    logActivity("Sign up");
  }

  /* User Login/Signin controller  */
  async postSignin(req, res) {
    let { email, password } = req.body;
    if (!email || !password) {
      return res.json({
        error: "Fields must not be empty",
      });
    }
    try {
      const data = await userModel.findOne({ email: email });
      if (!data) {
        return res.json({
          error: "Invalid email or password",
        });
      } else {
        const login = await bcrypt.compare(password, data.password);
        if (login) {
          const token = jwt.sign(
            { _id: data._id, role: data.userRole },
            JWT_SECRET
          );
          const encode = jwt.verify(token, JWT_SECRET);

          logActivity("Sign in");

          return res.json({
            token: token,
            user: encode,
          });
        } else {
          return res.json({
            error: "Invalid email or password",
          });
        }
      }
    } catch (err) {
      console.log(err);
    }
  }
}

const authController = new Auth();
module.exports = authController;
