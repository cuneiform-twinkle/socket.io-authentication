const http = require('http');
const ioServer = require('socket.io');
const app = require('./app');
const User = require('./userModel');
const jwt = require('jsonwebtoken');



const PORT=process.env.PORT
const httpServer = http.createServer(app);


const io = ioServer(httpServer);


io.use(async (socket, next) => {
        try {
            const token = socket.handshake.auth.token;
            const decoded = jwt.verify(token, process.env.SECRET_KEY);
            const user = await User.findById(decoded.userId);
            if (!user) {
                throw new Error('User not found');
            }

            // Attach the user object to the socket
            socket.user = user;
            next();
        } catch (error) {
            console.error('Authentication error', error);
            next(new Error('Authentication error'));
        }
    });


    io.on('connection', (socket) => {
        console.log(socket.id)
    })

    httpServer.listen(PORT, () => {
        console.log(` Server started running at ${PORT}`);
    });


    module.exports = io;


