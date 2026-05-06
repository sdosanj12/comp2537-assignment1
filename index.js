require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

const mongoUri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

let userCollection;

async function connectDB() {
  const client = new MongoClient(mongoUri);
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE);
  userCollection = db.collection('users');
  console.log('Connected to MongoDB');
}

app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: mongoUri,
    dbName: process.env.MONGODB_DATABASE,
    collectionName: 'sessions',
    crypto: { secret: process.env.MONGODB_SESSION_SECRET }
  }),
  cookie: { maxAge: 60 * 60 * 1000 }
}));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}

app.get('/', (req, res) => {
  if (req.session.user) {
    res.send(`<!DOCTYPE html><html><head><title>Home</title></head><body>
      <h1>Hello, ${req.session.user.name}!</h1>
      <a href="/members"><button>Go to Members Area</button></a><br><br>
      <a href="/logout"><button>Logout</button></a>
    </body></html>`);
  } else {
    res.send(`<!DOCTYPE html><html><head><title>Home</title></head><body>
      <h1>Welcome</h1>
      <a href="/signup"><button>Sign up</button></a><br><br>
      <a href="/login"><button>Log in</button></a>
    </body></html>`);
  }
});

app.get('/signup', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Sign Up</title></head><body>
    <h2>create user</h2>
    <form action="/signupSubmit" method="POST">
      <input name="name" placeholder="name" /><br>
      <input name="email" placeholder="email" /><br>
      <input name="password" type="password" placeholder="password" /><br>
      <button type="submit">Submit</button>
    </form>
  </body></html>`);
});

app.post('/signupSubmit', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) return res.send(`<p>Name is required.</p><a href="/signup">Try again</a>`);
  if (!email) return res.send(`<p>Please provide an email address.</p><a href="/signup">Try again</a>`);
  if (!password) return res.send(`<p>Password is required.</p><a href="/signup">Try again</a>`);

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(100).required()
  });

  const { error } = schema.validate({ name, email, password });
  if (error) return res.send(`<p>Invalid input: ${error.details[0].message}</p><a href="/signup">Try again</a>`);

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.user = { name, email };
  res.redirect('/members');
});

app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Log In</title></head><body>
    <h2>log in</h2>
    <form action="/loginSubmit" method="POST">
      <input name="email" placeholder="email" /><br>
      <input name="password" type="password" placeholder="password" /><br>
      <button type="submit">Submit</button>
    </form>
  </body></html>`);
});

app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(100).required()
  });

  const { error } = schema.validate({ email, password });
  if (error) return res.send(`<p>Invalid input.</p><a href="/login">Try again</a>`);

  const user = await userCollection.findOne({ email });
  if (!user) return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);

  req.session.user = { name: user.name, email: user.email };
  res.redirect('/members');
});

app.get('/members', requireLogin, (req, res) => {
  const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`<!DOCTYPE html><html><head><title>Members</title></head><body>
    <h1>Hello, ${req.session.user.name}.</h1>
    <img src="/${randomImage}" alt="random image" width="300" /><br><br>
    <a href="/logout"><button>Sign out</button></a>
  </body></html>`);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('*', (req, res) => {
  res.status(404).send(`<!DOCTYPE html><html><head><title>404</title></head><body>
    <h1>Page not found - 404</h1>
  </body></html>`);
});

// Server only starts AFTER MongoDB is connected
connectDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => {
    console.error('Failed to connect to MongoDB:', err);
    process.exit(1);
  });