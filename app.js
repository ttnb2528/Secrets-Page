import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import cookieParser from "cookie-parser";
import passportLocal from "passport-local";
// Add crypto library to pgAdmin to use crypt in queries

const app = express();
const port = 3000;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Secrets",
  password: "Tan281201!",
  port: 5432,
});

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
// set the default view engine to ejs, like find file dot ejs and render them
app.set("view engine", "ejs");

// config the session
app.use(
  session({
    secret: "Our little secret.",
    resave: true,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === "production" },
  })
);

app.use(cookieParser());

// config passport to initialize and use session
app.use(passport.initialize());
app.use(passport.session());

// passport.use(
//   new passportLocal.Strategy(function (username, password, done) {
//     db.query(
//       "SELECT * FROM users WHERE username = $1 AND password = crypt($2, password);",
//       [username, password],
//       (err, result) => {
//         if (err) {
//           return done(err);
//         }

//         if (result.rows.length > 0) {
//           return done(null, result.rows[0]);
//         } else {
//           return done(null, false);
//         }
//       }
//     );
//   })
// );

db.connect();

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/secrets", (req, res) => {
  if (req.session.user) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    // Should use 8-16 bytes to ensure security, and default is 16
    const result = await db.query(
      "insert into users (username, password) values ($1, crypt($2, gen_salt('bf', 8))) returning *;",
      [username, password]
    );

    req.session.user = result.rows[0];
    console.log(req.session.user);
    res.render("secrets");
  } catch (err) {
    res.render("register", {
      error: "Something went wrong, let try again!",
    });

    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const result = await db.query(
      "SELECT * FROM users WHERE username = $1 AND password = crypt($2, password);",
      [username, password]
    );

    if (result.rows.length > 0) {
      req.session.user = result.rows[0];
      console.log(req.session.user);
      res.render("secrets");
    } else {
      res.render("login", {
        error: "Username or password is incorrect!",
      });
    }
  } catch (err) {
    res.render("login", {
      error: "Username or password is incorrect!",
    });
  }
});

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
