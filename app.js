require('dotenv').config();
const express = require('express');
const http = require('http');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const util = require('util'); // For promisifying jwt.sign
const cors = require('cors');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const Users = require('./models/User');

const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 8000;

// Promisify jwt.sign for async/await usage
const jwtSignPromise = util.promisify(jwt.sign);

// Initialize Socket.IO
const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL,
        methods: ["GET", "POST"]
    }
});

// Connect to MongoDB
// Assuming './db/connection' sets up the mongoose connection
// Example if it were inline:
// mongoose.connect(process.env.MONGO_URI)
//     .then(() => console.log('MongoDB Connected Successfully!'))
//     .catch(err => console.error('MongoDB connection error:', err));
require('./db/connection'); // Keep this if your connection logic is in this file

// Import Models
const Users = require('./models/User'); // Corrected path to 'User' singular as per common practice
const Conversation = require('./models/Conversation');
const Messages = require('./models/Messages');

// Middleware for Express REST API
app.use(express.json()); // For parsing application/json bodies
app.use(cors({ // Apply CORS middleware for all Express routes
    origin: process.env.FRONTEND_URL,
    methods: ["GET", "POST", "PUT", "DELETE"]
}));


// --- Socket.IO Logic ---
let users = [];

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('addUser', userId => {
        // Update user's socketId if already exists, otherwise add new user
        const existingUserIndex = users.findIndex(user => user.userId === userId);
        if (existingUserIndex !== -1) {
            users[existingUserIndex].socketId = socket.id;
        } else {
            users.push({ userId, socketId: socket.id });
        }
        io.emit('getUsers', users);
        console.log('Users online:', users);
    });

    socket.on('sendMessage', async ({ senderId, receiverId, message, conversationId, user }) => {
        const receiverSocketInfo = users.find(onlineUser => onlineUser.userId === receiverId);
        const senderSocketInfo = users.find(onlineUser => onlineUser.userId === senderId);

        const messageData = {
            senderId,
            receiverId,
            conversationId,
            message,
            user: user || null,
            createdAt: new Date().toISOString()
        };

        if (receiverSocketInfo) {
            io.to(receiverSocketInfo.socketId).emit('getMessage', messageData);
        }

        // We only emit back to the sender if they are not the one who initiated the optimistic update
        // (This is primarily handled on the client-side now, but keeping server echo can be useful for debugging
        // or if client-side optimistic update is not present)
        if (senderSocketInfo && senderId !== receiverId) { // Avoid sending back to self unless it's a self-chat
             io.to(senderSocketInfo.socketId).emit('getMessage', messageData);
        }
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected:', socket.id);
        users = users.filter(user => user.socketId !== socket.id);
        io.emit('getUsers', users);
        console.log('Remaining online users:', users);
    });
});

// --- REST API Routes ---

// Basic welcome route
app.get('/', (req, res) => {
    res.status(200).send('Welcome to the Chat App Server!');
});

// User Registration Route
app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        if (!fullName || !email || !password) {
            return res.status(400).json({ error: 'Please fill all fields.' });
        }

        const existingUser = await Users.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email.' });
        }

        const hashedPassword = await bcryptjs.hash(password, 10); // Hash password

        const newUser = new Users({ fullName, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully!' }); // 201 Created for new resource

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'An error occurred during registration.' });
    }
});

// User Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Please fill all fields.' });
        }

        const user = await Users.findOne({ email }).select('+password'); // Select password explicitly
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials.' }); // Generic message for security
        }

        const isPasswordValid = await bcryptjs.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        const payload = {
            userId: user._id,
            userEmail: user.email
        };

        const JWT_SECRETE_KEY = process.env.JWT_SECRETE_KEY || 'A_VERY_STRONG_DEFAULT_JWT_SECRET_KEY_PLEASE_CHANGE_ME';
        const token = await jwtSignPromise(payload, JWT_SECRETE_KEY, { expiresIn: '1d' });

        res.status(200).json({
            User: {
                id: user._id,
                email: user.email,
                fullName: user.fullName
            },
            token: token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'An error occurred during login.' });
    }
});

// Create Conversation Route
app.post('/api/conversation', async (req, res) => {
    try {
        const { senderId, receiverId } = req.body;

        const existingConversation = await Conversation.findOne({
            Members: { $all: [senderId, receiverId] }
        });

        if (existingConversation) {
            return res.status(200).json({
                message: 'Conversation already exists',
                conversationId: existingConversation._id
            });
        }

        const conversation = new Conversation({ Members: [senderId, receiverId] });
        await conversation.save();
        res.status(201).json({
            message: "Conversation created successfully",
            conversationId: conversation._id
        });
    } catch (error) {
        console.error('Error creating conversation:', error);
        res.status(500).json({ error: 'An error occurred while creating the conversation.' });
    }
});

// Get Messages for a specific Conversation ID or check for existing conversation
app.get('/api/message/:conversationId', async (req, res) => {
    try {
        const { conversationId } = req.params;

        if (conversationId === 'new') { // Handles client request to check for new conversation
            const { senderId, receiverId } = req.query;
            if (!senderId || !receiverId) {
                return res.status(400).json({ error: 'SenderId and ReceiverId are required for new conversation check.' });
            }

            const checkConversation = await Conversation.findOne({
                Members: { $all: [senderId, receiverId] }
            });

            if (checkConversation) {
                return res.status(200).json({ conversationId: checkConversation._id, message: 'Existing conversation found' });
            } else {
                return res.status(200).json({ message: 'No conversation found for these members' });
            }
        } else { // Fetches messages for an existing conversationId
            const messages = await Messages.find({ ConversationId: conversationId });

            if (messages.length === 0) {
                return res.status(200).json([]);
            }

            const messageUserData = await Promise.all(
                messages.map(async (message) => {
                    const user = await Users.findById(message.SenderId);
                    return user
                        ? {
                            user: { id: user._id.toString(), fullName: user.fullName, email: user.email },
                            message: message.Message,
                            createdAt: message.createdAt
                        }
                        : null;
                })
            );

            const filteredData = messageUserData.filter(data => data !== null);
            return res.status(200).json(filteredData);
        }
    } catch (error) {
        console.error('Error fetching conversation or messages:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// POST Route to Send and Save a Message (Crucial for Persistence)
app.post('/api/message', async (req, res) => {
    try {
        const { conversationId, senderId, message, receiverId } = req.body;

        if (!senderId || !message) {
            return res.status(400).json({ error: 'SenderId and Message are required.' });
        }

        let actualConversationId = conversationId;

        if (!actualConversationId && receiverId) {
            let existingConversation = await Conversation.findOne({
                Members: { $all: [senderId, receiverId] }
            });

            if (!existingConversation) {
                const newConversation = new Conversation({
                    Members: [senderId, receiverId]
                });
                await newConversation.save();
                actualConversationId = newConversation._id;
            } else {
                actualConversationId = existingConversation._id;
            }
        } else if (!actualConversationId && !receiverId) {
            return res.status(400).json({ error: 'Please provide either conversationId or receiverId for message persistence.' });
        }

        const newMessages = new Messages({
            ConversationId: actualConversationId,
            SenderId: senderId,
            Message: message
        });
        await newMessages.save();

        res.status(200).json({
            message: 'Message sent and saved successfully',
            conversationId: actualConversationId
        });

    } catch (error) {
        console.error('Error saving message:', error);
        res.status(500).json({ error: 'An error occurred while saving the message.' });
    }
});

// Get Conversations for a specific User
app.get('/api/conversation/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const conversations = await Conversation.find({ Members: { $in: [userId] } });

        if (conversations.length === 0) {
            return res.status(200).json([]);
        }

        const conversationUserData = await Promise.all(
            conversations.map(async (conv) => {
                const receiverId = conv.Members.find((member) => member.toString() !== userId);

                if (!receiverId || !mongoose.Types.ObjectId.isValid(receiverId)) {
                    console.warn(`Invalid or missing receiver ID for conversation ${conv._id}`);
                    return null;
                }

                const user = await Users.findById(receiverId); // Mongoose handles ObjectId conversion here implicitly

                if (!user) {
                    console.warn(`User with ID ${receiverId} not found for conversation ${conv._id}`);
                    return null;
                }

                return {
                    user: {
                        receiverId: user._id.toString(),
                        fullName: user.fullName,
                        email: user.email,
                    },
                    conversationId: conv._id.toString(),
                };
            })
        );

        const filteredConversations = conversationUserData.filter(data => data !== null);
        res.status(200).json(filteredConversations);
    } catch (error) {
        console.error('Error fetching conversation list:', error);
        res.status(500).json({ message: 'An error occurred while fetching conversations.' });
    }
});

// Get All Users
app.get('/api/users', async (req, res) => {
    try {
        const users = await Users.find();
        const usersData = users.map((user) => ({
            id: user._1id.toString(),
            fullName: user.fullName,
            email: user.email,
        }));
        res.status(200).json(usersData);
    } catch (error) {
        console.error('Error fetching all users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Get a single conversation by senderId and receiverId
app.get('/api/conversation/check', async (req, res) => { // Changed path to avoid conflict with /:userId
    const { senderId, receiverId } = req.query;
    try {
        const conversation = await Conversation.findOne({
            Members: { $all: [senderId, receiverId] }
        });

        if (conversation) {
            return res.status(200).json({ conversationId: conversation._id });
        } else {
            return res.status(404).json({ message: 'No conversation found' });
        }
    } catch (error) {
        console.error('Error fetching specific conversation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Start the shared HTTP server
server.listen(port, () => {
    console.log(`Server (Express and Socket.IO) started on port ${port}`);
});