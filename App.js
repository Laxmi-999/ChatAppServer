const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const io = require('socket.io')(8080, {
    cors :{
        origin:'http://localhost:3000'
    }
});

//Connecting Db
require('./db/connection');

//importing files
const Users = require('./models/Users');
const Conversation = require('./models/Conversation');
const Messages = require('./models/Messages');
const mongoose = require('mongoose');




//app use
app.use(express.json());

app.use(cors());
// app.use(express.urlencoded({ extended: false }));
const port = 8000;




//socket.io
// for main connection 
let users = [];

io.on('connection', socket => {
    // inside it, performs two action 

    console.log('user connected', socket.id);
    //when server is receiving something from frontend it performs socket.on
            socket.on('addUser', userId =>{

                const isUserExist = users.find(user => user.userId === userId)
                
                if(!isUserExist)
                    {
                    const user = {userId, socketId: socket.id}
                    users.push(user);
                    // console.log('users are ', users);
                    io.emit('getUsers', users);
                } 

    });
      

    socket.on('sendMessage', async({ senderId, receiverId, message, conversationId}) =>{

        const receiver = users.find(user => user.userId === receiverId);
        const sender = users.find(user => user.userId === senderId);

        const user = await Users.findById(senderId);


        console.log('user or sender  is  ', user);
        console.log('sender is ', sender);
        console.log('receiver is ', receiver);

        if (receiver && sender) {

            io.to(receiver.socketId).to(sender.socketId).emit('getMessage', {
                senderId,
                receiverId,
                conversationId,
                message,
                user:{id:user._id, fullName:user.fullName, email:user.email}

            });
        }else{
            io.to(sender.socketId).emit('getMessage', {
                senderId,
                receiverId,
                conversationId,
                message,
                user:{id:user._id, fullName:user.fullName, email:user.email}

            });
        }
    });
    socket.on('disconnect', () =>{
        users = users.filter(user => user.socketId !== socket.id);
        io.emit('getUsers', users);
    });

});


//routes
app.get('/', (req, res) => {
    res.send('welcome');
    res.end();
    // console,log('welcome');
});

app.post('/api/register', async (req, res) => {
    try {
        // console.log(req.body);
        const { fullName, email, password } = req.body;
        // console.log(email);

        if (!fullName || !email || !password) {
            res.status(400).send('please fill all the fields');
        } else {
            const isAlreadyExits = await Users.findOne({ email });
            if (isAlreadyExits) {
                res.status(400).send('user  already exist');
            }
            else {
                const newUser = new Users({ fullName, email });
                bcryptjs.hash(password, 10, (err, hashedPassword) => {
                    newUser.set('password', hashedPassword);
                    newUser.save();
                    // next();

                })
                return res.status(200).send('User registered successfully');
            }
        }
    } catch (Err) {
        console.log(Err, 'error');
    }
})

app.post('/api/login', async (req, res, next) => {

    try {

        const { email, password } = req.body;

        if (!email || !password) {
            res.status(400).send('please fill all the fields');
        }
        else {
            const User = await Users.findOne({ email });
            if (!User) {
                res.status(400).send('user not found !');
            } else {
                const ValidateUser = await bcryptjs.compare(password, User.password);
                if (!ValidateUser) {
                    res.status.apply(400).send('incorrect email or password');

                } else {
                    const payload = {
                        userId: User.id,
                        userEmail: User.email
                    }
                    const JWT_SECRETE_KEY = process.env.JWT_SECRETE_KEY || 'THIS_IS_JWT_SECRETE_KEY';
                    jwt.sign(payload, JWT_SECRETE_KEY, { expiresIn: 84600 }, async (err, token) => {

                        await Users.updateOne({ _id: User._id }, {
                            $set: { token }
                        })
                        User.save();
                        next();
                    })
                    res.status(200).json({ User: { id: User._id, email: User.email, fullName: User.fullName }, token: User.token });


                }
            }

        }
    } catch (error) {
        console.log(error, 'error');

    }

})
app.post('/api/conversation', async (req, res) => {
    try {
        const { senderId, receiverId } = req.body;
        const conversation = new Conversation({ Members: [senderId, receiverId] });
        await conversation.save();
        res.status(200).send("conversation created successfully");
    } catch (error) {
        console.log(error, 'error');
    }
})


app.get('/api/message/:conversationId', async (req, res) => {
    try {
        const conversationId = req.params.conversationId;
        // console.log('conversation ID is ', conversationId)


        if (conversationId === 'new') {
            // Handle new conversation
            const checkConversation = await Conversation.find({
                members: { $all: [req.query.senderId, req.query.receiverId] }
            });

            if (checkConversation.length > 0) {
                return res.status(200).json({ conversationId: checkConversation[0]._id });
            } else {
                // If no conversation exists, create a new one or return a message
                return res.status(200).json({ message: 'No conversation found' });
            }
        } else {
            // Handle existing conversation messages
            const messages = await Messages.find({ ConversationId: conversationId });

            if (messages.length === 0) {
                return res.status(200).json([]); // No messages
            }

            // Fetch user data for each message
            const messageUserData = await Promise.all(
                messages.map(async (message) => {
                    const user = await Users.findById(message.SenderId);
                    return user
                        ? {
                              user: { id: user._id, fullName: user.fullName, email: user.email },
                              message: message.Message,
                          }
                        : null;
                })
            );

            // Filter out any null values if a user was not found
            const filteredData = messageUserData.filter(data => data !== null);

            return res.status(200).json(filteredData);
        }
    } catch (error) {
        console.error('Error fetching conversation or messages:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



        // Corrected Backend Responses
        app.post('/api/message', async (req, res) => {
            try {
                console.log(req.body);
                const { conversationId, senderId, message, receiverId = "" } = req.body;

                if (!senderId || !message)
                    return res.status(400).json({ error: 'Please fill all the fields' });

                if (conversationId === 'new' && receiverId) {
                    const NewConversation = new Conversation({
                        Members: [senderId, receiverId]
                    });
                    await NewConversation.save();

                    const newMessages = new Messages({
                        ConversationId: NewConversation._id,
                        SenderId: senderId,
                        Message: message
                    });
                    await newMessages.save();
                    return res.status(200).json({ message: 'Message sent successfully' });
                }

                if (!conversationId && !receiverId) {
                    return res.status(400).json({ error: 'Please provide either conversationId or receiverId' });
                }

                const newMessages = new Messages({
                    ConversationId: conversationId,
                    SenderId: senderId,
                    Message: message
                });
                await newMessages.save();
                res.status(200).json({ message: 'Message sent successfully' });
            } catch (error) {
                console.error(error);
                res.status(500).json({ error: 'An error occurred while sending the message' });
            }
        });



app.get('/api/conversation/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        console.log(userId);

        const conversation = await Conversation.find({ Members: { $in: [userId] } });

        if (conversation.length === 0) {
            return res.status(200).json({ message: 'No conversations found. Start a new chat!' });
        }

        const conversationUserData = await Promise.all(
            conversation.map(async (conversation) => {
                // Find the other member in the conversation
                const receiverId = conversation.Members.find((member) => member !== userId) || userId;

                if (!mongoose.Types.ObjectId.isValid(receiverId)) {
                    console.error(`Receiver ID not found for conversation ${conversation._id}`);
                    return { error: `Receiver ID not found`, conversationId: conversation._id.toString() };
                }

                const user = await Users.findById(new mongoose.Types.ObjectId(receiverId));

                if (!user) {
                    console.error(`User with ID ${receiverId} not found`);
                    return { error: `User with ID ${receiverId} not found`, conversationId: conversation._id.toString() };
                }

                return {
                    user: {
                        receiverId: user._id.toString(),
                        fullName: user.fullName,
                        email: user.email,
                        isSender: receiverId === userId
                    },
                    conversationId: conversation._id.toString()
                };
            })
        );

        res.status(200).json(conversationUserData);
    } catch (error) {
        console.error('Error fetching conversation:', error);
        res.status(500).json({ message: 'An error occurred while fetching conversations.' });
    }
});



app.get('/api/users', async (req, res) => {
    try {
        const users = await Users.find();
        const usersData = Promise.all(users.map(async (user) => {
            return { users: { fullName: user.fullName, email: user.email, receiverId: user._id }, }
        }))
        res.status(200).json(await usersData);
    } catch (error) {

        console.log('error', error);

    }
})

app.get('/api/conversation', async (req, res) => {
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
        console.error('Error fetching conversation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.listen(port, () => {
    console.log(`server started on  ${port}`);

});