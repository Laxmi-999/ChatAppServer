require('dotenv').config();
const express = require('express');
const http = require('http');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app); //  Create shared HTTP server
const port = process.env.PORT || 8000;



// Initialize socket.io with the shared server
const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL,
        methods: ["GET", "POST"]
    }
});

// Connect to MongoDB
require('./db/connection');

// Import Models
const Users = require('./models/Users');
const Conversation = require('./models/Conversation');
const Messages = require('./models/Messages');

// Middleware
app.use(express.json());
app.use(cors());



//socket logic
let users = [];

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('addUser', userId => {
        if (!users.some(user => user.userId === userId)) {
            users.push({ userId, socketId: socket.id });
        } else {
            const existingUserIndex = users.findIndex(user => user.userId === userId);
            if (existingUserIndex !== -1) {
                users[existingUserIndex].socketId = socket.id;
            }
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

        if (senderSocketInfo) {
            io.to(senderSocketInfo.socketId).emit('getMessage', messageData);
        }
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected:', socket.id);
        users = users.filter(user => user.socketId !== socket.id);
        io.emit('getUsers', users);
    });
});

// =====================================
// REST API Routes
// =====================================

// Basic welcome route for the server
app.get('/', (req, res) => {
    res.send('Welcome to the Chat App Server!');
});

// User Registration Route
app.post('/api/register', async (req, res) => {
    try {
        console.log('Register request body:', req.body);
        const { fullName, email, password } = req.body;

        // Validate required fields
        if (!fullName || !email || !password) {
            return res.status(400).send('Please fill all the fields');
        }

        // Check if user already exists
        const isAlreadyExits = await Users.findOne({ email });
        if (isAlreadyExits) {
            return res.status(400).send('User already exist');
        }

        // Create new user and hash password
        const newUser = new Users({ fullName, email });
        bcryptjs.hash(password, 10, async (err, hashedPassword) => {
            if (err) {
                console.error("Error hashing password:", err);
                return res.status(500).json({ error: 'Failed to register user.' });
            }
            newUser.set('password', hashedPassword);
            await newUser.save(); // Save the new user to DB
            return res.status(200).send('User registered successfully');
        });

    } catch (Err) {
        console.error('Registration error:', Err);
    res.status(500).json({ error: 'An error occurred during registration.' })
    }
});

// User Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login request body:', req.body);

        // Validate required fields
        if (!email || !password) {
            return res.status(400).send('Please fill all the fields');
        }

        // Find user by email
        const User = await Users.findOne({ email });
        if (!User) {
            console.log("User not found for email:", email);
            return res.status(400).send('User not found!');
        }

        // Validate password
        const ValidateUser = await bcryptjs.compare(password, User.password);
        if (!ValidateUser) {
            return res.status(400).send('Incorrect email or password');
        }

        // Generate JWT token
        const payload = {
            userId: User._id,
            userEmail: User.email
        };
        // Use environment variable for JWT secret key, with a fallback
        const JWT_SECRETE_KEY = process.env.JWT_SECRETE_KEY || 'THIS_IS_A_VERY_STRONG_DEFAULT_JWT_SECRETE_KEY'; // Changed default key for better security

        jwt.sign(payload, JWT_SECRETE_KEY, { expiresIn: '1d' }, async (err, token) => { // '1d' for 1 day expiration
            if (err) {
                console.error("JWT sign error:", err);
                return res.status(500).json({ error: 'Failed to generate token.' });
            }

            // Update user's token in the database
            await Users.updateOne({ _id: User._id }, {
                $set: { token: token }
            });

            console.log('User logged in successfully');
            console.log(`Logged in user details: ID - ${User._id}, Email - ${User.email}, Full Name - ${User.fullName}`);

            // Respond with user details and token
            return res.status(200).json({
                User: {
                    id: User._id, // Use 'id' for consistency with client if preferred
                    email: User.email,
                    fullName: User.fullName
                },
                token: token
            });
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'An error occurred during login.' });
    }
});

// Create Conversation Route (Note: This is mostly for initial conversation creation,
// the /api/message POST route also handles 'new' conversation creation if needed)
app.post('/api/conversation', async (req, res) => {
    try {
        const { senderId, receiverId } = req.body;
        // Check if a conversation already exists between these members to avoid duplicates
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
        res.status(200).json({
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
        const conversationId = req.params.conversationId;

        // If the client requests 'new', it means they are checking for an existing conversation
        // or preparing to start a new one with a specific sender/receiver pair.
        if (conversationId === 'new') {
            const { senderId, receiverId } = req.query;
            if (!senderId || !receiverId) {
                return res.status(400).json({ error: 'SenderId and ReceiverId are required for new conversation check.' });
            }

            // Find if a conversation already exists between these two users
            const checkConversation = await Conversation.find({
                Members: { $all: [senderId, receiverId] }
            });

            if (checkConversation.length > 0) {
                // If conversation exists, return its ID
                return res.status(200).json({ conversationId: checkConversation[0]._id, message: 'Existing conversation found' });
            } else {
                // If no conversation found, indicate that (client will then use /api/message POST to create it)
                return res.status(200).json({ message: 'No conversation found for these members' });
            }
        } else {
            // If a specific conversationId is provided, fetch messages for it
            const messages = await Messages.find({ ConversationId: conversationId });

            if (messages.length === 0) {
                return res.status(200).json([]); // Return empty array if no messages
            }

            // Populate user details for each message
            const messageUserData = await Promise.all(
                messages.map(async (message) => {
                    // Mongoose's .populate() could be more efficient here, but manual lookup works too.
                    const user = await Users.findById(message.SenderId);
                    return user
                        ? {
                            user: { id: user._id, fullName: user.fullName, email: user.email }, // Ensure consistent 'id'
                            message: message.Message, // Use 'Message' as it's from the schema
                            createdAt: message.createdAt // Include timestamp for sorting on client
                        }
                        : null; // Handle case where sender user might not be found
                })
            );

            // Filter out any messages where the sender user couldn't be found
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
        console.log("Received message data for saving:", req.body);
        const { conversationId, senderId, message, receiverId } = req.body; // receiverId is expected for 'new' conversations

        // Basic validation
        if (!senderId || !message) {
            return res.status(400).json({ error: 'SenderId and Message are required.' });
        }

        let actualConversationId = conversationId;

        // If conversationId is not provided (or explicitely 'new' from client payload design)
        // and a receiverId is available, try to find or create a new conversation.
        if (!actualConversationId && receiverId) {
            // Check if conversation already exists between sender and receiver
            let existingConversation = await Conversation.findOne({
                Members: { $all: [senderId, receiverId] }
            });

            if (!existingConversation) {
                // If no existing conversation, create a new one
                const NewConversation = new Conversation({
                    Members: [senderId, receiverId]
                });
                await NewConversation.save();
                actualConversationId = NewConversation._id; // Set the new conversation ID
                console.log('New conversation created for message:', actualConversationId);
            } else {
                actualConversationId = existingConversation._id; // Use existing conversation ID
                console.log('Using existing conversation for message:', actualConversationId);
            }
        } else if (!actualConversationId && !receiverId) {
            // This case should ideally not happen if client sends conversationId or receiverId for 'new'
            return res.status(400).json({ error: 'Please provide either conversationId or receiverId for message persistence.' });
        }

        // Create and save the new message
        const newMessages = new Messages({
            ConversationId: actualConversationId,
            SenderId: senderId,
            Message: message
        });
        await newMessages.save();
        console.log('Message saved to DB:', newMessages._id);

        // Respond with success and the conversationId (especially useful if a new one was created)
        res.status(200).json({
            message: 'Message sent and saved successfully',
            conversationId: actualConversationId // Return the actual conversation ID used
        });

    } catch (error) {
        console.error('Error saving message:', error);
        res.status(500).json({ error: 'An error occurred while saving the message.' });
    }
});

// Get Conversations for a specific User
app.get('/api/conversation/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        console.log('Fetching conversations for user ID:', userId);

        // Find all conversations where the userId is a member
        const conversations = await Conversation.find({ Members: { $in: [userId] } });

        if (conversations.length === 0) {
            return res.status(200).json([]); // Return empty array if no conversations
        }

        // For each conversation, get the details of the other member
        const conversationUserData = await Promise.all(
            conversations.map(async (conv) => {
                // Find the ID of the other member in the conversation (not the current user)
                const receiverId = conv.Members.find((member) => member.toString() !== userId); // Use toString() for comparison

                if (!receiverId) {
                    console.error(`Receiver ID not found in conversation ${conv._id}`);
                    return null; // Skip this conversation if other member ID is missing
                }

                // Ensure receiverId is a valid ObjectId before querying
                if (!mongoose.Types.ObjectId.isValid(receiverId)) {
                    console.error(`Invalid receiver ID for conversation ${conv._id}: ${receiverId}`);
                    return null;
                }

                // Find the user details of the other member
                const user = await Users.findById(new mongoose.Types.ObjectId(receiverId));

                if (!user) {
                    console.error(`User with ID ${receiverId} not found for conversation ${conv._id}`);
                    return null; // Skip if user details not found
                }

                // You might also want to fetch the last message here and pass it
                // For simplicity, we're not fetching last message/unread count in this specific endpoint
                // but client side can update unreadCount on its own from socket.on('getMessage')
                return {
                    user: {
                        receiverId: user._id.toString(), // Consistent receiverId
                        fullName: user.fullName,
                        email: user.email,
                        // Add other user details if needed, e.g., profile picture
                    },
                    conversationId: conv._id.toString(), // Consistent conversationId
                    // You can add unreadCount here if your Conversation model supports it
                };
            })
        );

        // Filter out any null entries (conversations where receiver details couldn't be fetched)
        const filteredConversations = conversationUserData.filter(data => data !== null);

        res.status(200).json(filteredConversations);
    } catch (error) {
        console.error('Error fetching conversation list:', error);
        res.status(500).json({ message: 'An error occurred while fetching conversations.' });
    }
});

// Get All Users (for starting new chats)
app.get('/api/users', async (req, res) => {
    try {
        const users = await Users.find();
        // Map to desired response format, including a consistent 'id' for the client
        const usersData = users.map((user) => {
            return {
                id: user._id.toString(), // Use user._id as 'id' for client
                fullName: user.fullName,
                email: user.email,
                // receiverId: user._id // Could also pass as receiverId for clarity if client prefers
            };
        });
        res.status(200).json(usersData);
    } catch (error) {
        console.error('Error fetching all users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Get a single conversation by senderId and receiverId (used by client for 'new' chat check)
app.get('/api/conversation', async (req, res) => {
    const { senderId, receiverId } = req.query;
    try {
        const conversation = await Conversation.findOne({
            Members: { $all: [senderId, receiverId] }
        });

        if (conversation) {
            // If conversation exists, return its ID
            return res.status(200).json({ conversationId: conversation._id });
        } else {
            // If no conversation found, inform the client. Client will then create via POST /api/message.
            return res.status(404).json({ message: 'No conversation found' });
        }
    } catch (error) {
        console.error('Error fetching specific conversation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Start the Express HTTP server
app.listen(port, () => {
    console.log(`Server started on ${port}`);
});
