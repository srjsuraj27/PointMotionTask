const express = require('express')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const auth = require('./middleware/auth');

const { body, check, validationResult } = require("express-validator");

const fs = require('fs');
var data = fs.readFileSync('db.json');
var users = JSON.parse(data);

const app = express();

// middlewares
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello World!')
})


// signup
app.post('/signup', 
  [
    body('username')
    .trim()
    .not()
    .isEmpty().withMessage('Please eneter username.')
    .isLength({ min: 4 }).withMessage('Username must be of 4 characters long.')
    .isAlpha().withMessage('Username must contain only alphabets.')
    .isLowercase().withMessage('Username must contain only lowercase English alphabets.'),
    body('password')
    .trim()
    .not()
    .isEmpty().withMessage('Please eneter password.')
    .isLength({ min: 5 }).withMessage('password must be of 5 characters long.')
    .isAlphanumeric().withMessage('password must contain only alphanumeric characters.')
    .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z\d@$.!%*#?&]/).withMessage('password must have atleast 1 Uppercase_char, 1 Lowercase_char, 1 Number.'),
    body('fname')
    .trim()
    .not()
    .isEmpty().withMessage('FirstName should not be Empty.')
    .isAlpha().withMessage('FirstName should only contain Alphabets!'),
    body('lname')
    .trim()
    .not()
    .isEmpty().withMessage('LastName should not be Empty.')
    .isAlpha().withMessage('LastName should only contain Alphabets!'),
  ],
  async (req, res) => {

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: errors.array()[0].msg
    });
  }

  const username = req.body.username;
  const password = req.body.password;
  const fname = req.body.fname;
  const lname = req.body.lname;

  // checking username already exist or not
  const result = users.filter(user => user.username === username);

  if(result.length !== 0){
    return res.status(400).json({ error: 'username already exists!' });
  } else {
    const hashedPw = await bcrypt.hash(password, 12)

    const user = {
      username: username,
      password: hashedPw,
      fname: fname,
      lname: lname,
      id: uuidv4()
    }

    users.push(user);

    var data = JSON.stringify(users, null, 2);
    fs.writeFile('db.json', data, () => {
      console.log('all set');
    });

    res.status(201).json({ 
      "result": true,
      "message": "SignUp success. Please proceed to Signin"
    });
  }
})


// signin
app.post('/signin', 
  [
    body('username')
    .trim()
    .not()
    .isEmpty().withMessage('Please enter Username.'),
    body('password')
    .trim()
    .not()
    .isEmpty().withMessage('Please enter Password.')
  ],
  async (req, res) => {

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: errors.array()[0].msg
    });
  }

  const { username, password } = req.body;

  const result = users.filter(user => user.username === username);
  // console.log(result[0].password);

  if(result.length === 0){
    return res.status(400).json({ error: 'username not found!' });
  } else {
    bcrypt.compare(password, result[0].password).then((match) => {
      if(!match) return res.status(400).json({ error: 'Invalid credentials' });

      jwt.sign(
        { id: result[0].id, username: result[0].username, fname: result[0].fname },
        'supersecret',
        { expiresIn: 3600 },
        (err, token) => {
            if(err) throw err;
            res.status(200).json({
                result: true,
                jwt: token,
                message: "Signin success",
                username: result[0].username,
                id: result[0].id
            })
        }
      )
    })
    .catch((err) => {
      if (err) {
        res.status(400).json({ error: err });
      }
    });
  }
})


// user-Info
app.get('/user/me', auth, (req, res) => {
  const user = req.user;
  const user_info = users.filter(usr => usr.id === user.id);
  res.status(200).send({ 
    "result": true,
    "data": {
        "fname": user_info[0].fname,
        "lname": user_info[0].lname,
        "password": user_info[0].password 
    }
   })
})

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

//PORT
const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
})