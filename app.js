import dotenv from "dotenv";
dotenv.config();
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import cookieParser from "cookie-parser";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
// Add crypto library to pgAdmin to use crypt in queries

const saltRounds = bcrypt.genSaltSync(10);

const app = express();
const port = 3000;

const db = new pg.Client({
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DB,
  password: process.env.POSTGRES_PASSWORD,
  port: process.env.POSTGRES_PORT,
});

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
// set the default view engine to ejs, like find file dot ejs and render them
app.set("view engine", "ejs");

// config the session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === "production" },
  })
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users");
      const user = result.rows.find((user) => username === user.username);

      if (user) {
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect password" });
          }
        });
      } else {
        return done(null, false, { message: "Incorrect username" });
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.username);
});

passport.deserializeUser(async (username, done) => {
  try {
    const result = await db.query(
      `SELECT * FROM users
          WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    done(null, user);
  } catch (error) {
    console.log("An error occured: ", error);
    done(error);
  }
});

app.use(cookieParser());

app.use(passport.initialize());
app.use(passport.session());

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
  if (req.isAuthenticated()) {
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
  // Hashing a password
  const plainPassword = password;
  const hashedPassword = bcrypt.hashSync(plainPassword, saltRounds);
  try {
    const response = await db.query(
      `INSERT INTO users (username, password)
                  VALUES ($1, $2)
                  RETURNING *`,
      [username, hashedPassword]
    );
    passport.authenticate("local")(req, res, function () {
      res.redirect("/secrets");
    });
  } catch (error) {
    console.log("An error occured: ", error);
  }

  // const plainPassword = password;
  //   bcrypt.hash(plainPassword, saltRounds, async (err, hash) => {
  //       // Store 'hash' in the database
  //       try {
  //           const response = await db.query(
  //               `INSERT INTO users (username, password)
  //                   VALUES ($1, $2)
  //                   RETURNING *`, [username, hash]
  //           );
  //           passport.authenticate('local')(req, res, function () {
  //               res.redirect('/secrets');
  //           })
 
  //       } catch (error) {
  //           console.log("An error occured: ", error);
  //       }
 
  //   });
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
