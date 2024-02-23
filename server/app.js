const express = require('express');
const http = require('http');
const ioServer = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./userModel');
const dbConfig = require('./dbConfig');
const app = express();
const httpServer = http.createServer(app);
const io = ioServer(httpServer);
const dotenv = require("dotenv");
const path = require("path");
const cors=require("cors");

const PORT = process.env.PORT || 3000;

app.use(express.json());
//app.use(express.static('public'));
dotenv.config();
app.use(cors())

dbConfig(process.env.LOCAL_URL, process.env.DB_NAME);



app.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, '../public/index.html'));
});

//Below method is also correct to render index.html
// app.use(express.static(path.join(__dirname, '../public')))
 
// app.get('/', function (req, res) {
//     res.render('index.html');
// })

app.post('/auth/register', registerUser);
app.post('/auth/login', loginUser);

// Register
async function registerUser(req, res) {
    try {
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.status(400).json({ message: 'Username or email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });
        await newUser.save();
        res.status(201).json({ message: 'Registration successful' });
    } catch (error) {
        console.error('Registration error', error);
        res.status(500).json({ message: 'Registration error' });
    }
}

// Login
async function loginUser(req, res) {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY);
        res.json({ token, message: 'Login successful' });
    } catch (error) {
        console.error('Login error', error);
        res.status(500).json({ message: 'Login error' });
    }
}

io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        const user = await User.findById(decoded.userId);
        if (!user) {
            throw new Error('User not found');
        }

        ``
        // Attach the user object to the socket
        socket.user = user;
        console.log(socket.user);
        next();
    } catch (error) {
        console.error('Authentication error', error);
        next(new Error('Authentication error'));
    }
});

io.on('connection', (socket) => {
    console.log(socket.id);
});

httpServer.listen(PORT, () => {
    console.log(`Server started running at http://localhost:${PORT}`);
});

module.exports = app;

// io.use:

// io.use is a method provided by Socket.IO to use middleware functions for handling events. In this case, it's used to add authentication middleware to the Socket.IO server.
// Middleware Function:

// The middleware function is defined with the parameters (socket, next).
// socket: Represents the socket connection that is being established.
// next: A function that must be called to proceed to the next middleware or the actual connection event.
// Token Extraction:

// const token = socket.handshake.auth.token;: Extracts the token from the authentication data in the socket handshake.
// The assumption is that the client includes an authentication token in the socket handshake when attempting to connect.
// Token Verification:

// const decoded = jwt.verify(token, process.env.SECRET_KEY);: Verifies the extracted token using the jwt.verify method. It uses the server's secret key (process.env.SECRET_KEY) to decode the token.
// If the verification fails (e.g., due to an expired or invalid token), it jumps to the catch block.
// User Retrieval:

// const user = await User.findById(decoded.userId);: Attempts to find a user in the database based on the decoded user ID from the token.
// If the user is not found, an error is thrown.
// Attach User to Socket:

// socket.user = user;: Attaches the retrieved user object to the socket. This allows you to access user information during subsequent socket events.
// For example, in other socket event handlers, you can use socket.user to get information about the authenticated user.
// Logging and next():

// console.log(socket.user);: Logs the user object to the console for debugging purposes.
// next();: Calls the next function to proceed to the next middleware or the actual connection event.
// Error Handling:

// In case of any errors during the token verification or user retrieval, the catch block is executed.
// It logs an authentication error and calls next(new Error('Authentication error')) to signal an authentication error and prevent the socket connection from being established.
// This middleware ensures that only authenticated users with valid tokens can establish a connection to the Socket.IO server. The authenticated user object is attached to the socket for use in handling real-time events.



















