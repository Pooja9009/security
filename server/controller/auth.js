const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/keys");
const userModel = require("../models/users");
const { validateEmail, toTitleCase } = require("../config/function");
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
    try {
      const { loggedInUserId } = req.body;
      const loggedInUserRole = await userModel.findById(loggedInUserId);
      res.json({ role: loggedInUserRole?.userRole });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch admin status" });
    }
  }

  async allUser(req, res) {
    try {
      const allUser = await userModel.find({});
      res.json({ users: allUser });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch all users" });
    }
    logActivity("find all user");
  }

  /* User Registration/Signup controller  */
  async postSignup(req, res) {
    const { name, email, password, cPassword } = req.body;

    try {
      // Validate inputs
      const error = {};
      if (!name || !email || !password || !cPassword) {
        error.name = "Field must not be empty";
        error.email = "Field must not be empty";
        error.password = "Field must not be empty";
        error.cPassword = "Field must not be empty";
      } else {
        if (name.length < 3 || name.length > 25) {
          error.name = "Name must be 3-25 characters";
        }

        if (password.length < 8 || password.length > 255) {
          error.password = "Password must be between 8 and 255 characters";
        }

        // Check if the password contains personal information
        if (
          password.toLowerCase().includes(name.toLowerCase()) ||
          password.toLowerCase().includes(email.toLowerCase())
        ) {
          error.password =
            "Password should not include personal information such as your name or email";
        }

        // Password complexity validation
        const passwordRegex =
          /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
          error.password =
            "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character";
        }

        // Check if the password is a common password
        if (commonPasswords.includes(password.toLowerCase())) {
          error.password =
            "This password is too common. Please choose a stronger one.";
        }

        if (!validateEmail(email)) {
          error.email = "Email is not valid";
        }
      }

      if (Object.keys(error).length > 0) {
        return res.json({ error });
      }

      const existingUser = await userModel.findOne({ email });
      if (existingUser) {
        return res.json({ error: { email: "Email already exists" } });
      }

      const hashedPassword = bcrypt.hashSync(password, 10);
      const newUser = new userModel({
        name: toTitleCase(name),
        email,
        password: hashedPassword,
        userRole: 0, // Field Name change to userRole from role
        // userRole: 1, // Field Name change to userRole from role
      });

      await newUser.save();
      return res.json({
        success: "Account created successfully. Please login",
      });
    } catch (error) {
      console.error("Error in postSignup:", error);
      res
        .status(500)
        .json({ error: "An error occurred while processing the request" });
    }
    logActivity("Sign up");
  }

  /* User Login/Signin controller  */
  async postSignin(req, res) {
    const { email, password } = req.body;
    try {
      const user = await userModel.findOne({ email });
      if (!user) {
        return res.json({ error: "Invalid email or password" });
      }

      const login = await bcrypt.compare(password, user.password);
      if (!login) {
        return res.json({ error: "Invalid email or password" });
      }

      const token = jwt.sign(
        { _id: user._id, role: user.userRole },
        JWT_SECRET
      );
      const encodedUser = jwt.verify(token, JWT_SECRET);

      logActivity("Sign in");

      return res.json({ token, user: encodedUser });
    } catch (error) {
      console.error("Error in postSignin:", error);
      res
        .status(500)
        .json({ error: "An error occurred while processing the request" });
    }
  }
}

const authController = new Auth();
module.exports = authController;
