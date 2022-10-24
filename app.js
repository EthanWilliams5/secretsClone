//jshint esversion:6

require("dotenv").config()
const express = require("express")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const ejs = require("ejs")
const _ = require("lodash")
const bcrypt = require('bcrypt');
const saltRounds = 10;
const myPlaintextPassword = 's0/\/\P4$$w0rD';
const someOtherPlaintextPassword = 'not_bacon';

const app = express()

app.use(express.static("public"))
app.set("view engine", "ejs")
app.use(bodyParser.urlencoded({extended: true}))

mongoose.connect("mongodb://localhost:27017/userDB")

const userSchema = new mongoose.Schema({
  email: String,
  password: String
}, { versionKey: false })

const secret = process.env.SECRET
const User = new mongoose.model("User", userSchema)


app.get("/", function(req, res) {
  res.render("home")
})


app.get("/login", function(req, res) {
  res.render("login")
})


app.get("/register", function(req, res) {
  res.render("register")
})

app.post("/register", function(req, res) {
  const email = req.body.username
  const password = req.body.password

  bcrypt.hash(password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: email,
      password: hash
    })
    newUser.save(function(err) {
      if(err) {
        console.log(err)
      } else {
        res.render("secrets")
      }
    })
  })
})

app.post("/login", function(req, res) {
  const email = req.body.username
  const password = req.body.password

  User.findOne({email: email}, function(err, foundUser) {
    if (err) {
      console.log(err)
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if (result) {
            res.render("secrets")
          }
        });
      }
    }
  })
})


app.listen(3000, function() {
  console.log("Server started on port 3000")
})