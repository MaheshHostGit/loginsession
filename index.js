import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";


const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//login session starts here//
//in this we have cookie age for 24 hrs, server save is false and complete save till 24 hrs is true//
app.use(session({
  secret:"TOPSECRETWORD",
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge : 1000*60*60*24,
  }
}));

//these two are madatory, so passport will initialize and session will start//
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "Mahesh",
  port: 5433,
});
db.connect();

//open home page//
app.get("/", (req, res) => {
  res.render("home.ejs");
});

//open login page//
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

//open register page
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

//comes here when register submit button presses//
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *" ,
            [email, hash]
          );
          const user = result.rows[0];
         req.login(user,(err) =>{
          console.log(err);
          res.redirect("/secrets");
         })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


//comes here when login submit button presses//
//if login sucess secrets route i.e, home page or main page opens//
app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect:"/login"
}));


//this is final route, where we call when the login or session is sucess//
app.get("/secrets", async(req,res) =>{
  console.log(req.user);
  if(req.isAuthenticated){
    res.render("secrets.ejs");
  }else{
    res.redirect("/login");
  }
})


//this method is used to check the login is valid or not and returns true or false where we can validate in login submit route//
passport.use(new Strategy(async function  verify(username, password, cb){

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null, user);
          } else {
            return cb(null , false);
          }
        }
      });
    } else {
      return cb("user not found")
    }
  } catch (err) {
    return cb(err);
  }

}))

passport.serializeUser((user,cb) => {
  cb(null,user);
})

passport.deserializeUser((user,cb) => {
  cb(null,user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
