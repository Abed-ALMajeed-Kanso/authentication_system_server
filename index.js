const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
// const { globalLimiter } = require('./middleware/ratelimiter');

dotenv.config(); 

const public = require('./router/public_users.js');
const authenticated = require('./router/authenticated_users.js');

const app = express();
app.set('trust proxy', 1)

app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));

// app.use(globalLimiter);
app.use(express.json());
app.use(cookieParser());

mongoose.connect(process.env.MONGO_DB_URI)
    .then(() => console.log("Connected to MongoDB"))
    .catch(err => console.error("MongoDB connection error:", err));

app.use('/authenticated', authenticated);
app.use('/', public);

app.listen(process.env.PORT, () => {
    console.log("Server is running");
});
