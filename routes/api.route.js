const router = require("express").Router();
var ironSession = require("iron-session/express").ironSession;

var session = ironSession({
  password: "complex_password_at_least_32_characters_long",
  cookieName: "express-with-auth-cookie",
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
});

const AuthController = require("../controllers/auth.controller");

function requestInterceptor(req, res, next) {
  // Intercept request
  console.log({ req });
  console.log("Request URL:", req.url);
  console.log("Request Method:", req.method);
  // You can modify the request object here if needed

  // Pass control to the next middleware or route handler
  next();
}

function responseInterceptor(req, res, next) {
  // Intercept response
  res.on("finish", () => {
    console.log("Response Status Code:", res.statusCode);
    // You can modify the response object here if needed
  });

  // Pass control to the next middleware or route handler
  next();
}

router.get("/", async (req, res, next) => {
  res.send({ message: "Ok api is working 🚀" });
});

// Authenticatino Routes
router.get("/me", session, AuthController.user);
router.get(
  "/users",
  session,
  requestInterceptor,
  responseInterceptor,
  AuthController.users
);
router.post("/login", session, AuthController.login);
router.post("/register", session, AuthController.register);

module.exports = router;
