//jshint esversion:6

require("dotenv").config()
const express = require("express")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const ejs = require("ejs")
const _ = require("lodash")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")

const app = express()

app.use(express.static("public"))
app.set("view engine", "ejs")
app.use(bodyParser.urlencoded({extended: true}))
app.use(session({
  secret: "Thesecret",
  resave: false,
  saveUninitialized: false
}))

app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema = new mongoose.Schema({
  email: String,
  password: String
}, { versionKey: false })

userSchema.plugin(passportLocalMongoose)

// const secret = process.env.SECRET
const User = new mongoose.model("User", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res) {
  res.render("home")
})


app.get("/login", function(req, res) {
  res.render("login")
})


app.get("/register", function(req, res) {
  res.render("register")
})


app.get("/secrets", function(req, res) {
  if (req.isAuthenticated) {
    res.render("secrets")
  } else {
    res.redirect("/login")
  }
})


// app.get("/logout", function(req, res, next){
//   req.logout(function(err) {
//     if (err) {
//       return next(err);
//     }
//     res.redirect("/");
//   });
// });
app.get("/logout", (req, res) => {
  req.logout(function(err) {
    if (err) {
      return next(err);
    } else {
    req.session.destroy(err => {
      if (!err) {
        res
          .status(200)
          .clearCookie("connect.sid", { path: "/" })
          .redirect("/");
      } else {
        console.log(err);
      }
    });
  }});
});


app.post("/register", function(req, res) {
  const email = req.body.username
  const password = req.body.password

  User.register({username: email}, password, function(err, user) {
    if (err) {
      console.log(err)
      res.redirect("/register")
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets")
      })
    }
  })
})

app.post("/login", function(req, res){
  //check the DB to see if the username that was used to login exists in the DB
  User.findOne({username: req.body.username}, function(err, foundUser){
    //if username is found in the database, create an object called "user" that will store the username and password
    //that was used to login
    if(foundUser){
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
      //use the "user" object that was just created to check against the username and password in the database
      //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
      //return the user found in the database
      passport.authenticate("local", function(err, user){
        if(err){
          console.log(err);
        } else {
          //this is the "user" returned from the passport.authenticate callback, which will be either
          //a false boolean value if no it didn't match the username and password or
          //a the user that was found, which would make it a truthy statement
          if(user){
            //if true, then log the user in, else redirect to login page
            req.login(user, function(err){
            res.redirect("/secrets");
            });
          } else {
            res.redirect("/login");
          }
        }
      })(req, res);
    //if no username is found at all, redirect to login page.
    } else {
      //user does not exists
      res.redirect("/login")
    }
  });
});


app.listen(3000, function() {
  console.log("Server started on port 3000")
})