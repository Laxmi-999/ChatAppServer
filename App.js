const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

//Connecting Db
require('./db/connection');

//importing files
const Users = require('./models/Users');
const Conversation = require('./models/Conversation');
const Messages = require('./models/Messages');




//app use
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
const port = 8000;



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
                    res.status(200).json({ User: { email: User.email, fullName: User.fullName }, token: User.token });


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
app.get('/api/conversation/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const conversation = await Conversation.find({ Members: { $in: [userId] } });
        const conversationUserData = Promise.all(conversation.map(async (conversation) => {
            const receiverId = conversation.Members.find((member) => member !== userId);
            const user = await Users.findById(receiverId);
            return { user: { fullName: user.fullName, email: user.email }, conversationId: conversation._id }
        }))
        res.status(200).json(await conversationUserData);

    } catch (error) {
        console.log(error, 'error');
    }
})
app.post('/api/message', async (req, res) => {
    try {
        console.log(req.body);
        const { conversationId, senderId, message, receiverId = "" } = req.body;
        if(!senderId || !message)
             return res.status(200).send('please fill  all the fields ');

      if(!conversationId && receiverId){
        const NewConversation = new Conversation({ Members: [senderId, receiverId] });
        await NewConversation.save();
        
        const newMessages = new Messages({ ConversationId: conversationId, SenderId: senderId, Message: message })
        await newMessages.save();
        res.status(200).send('Message sent successfully');
    }
    else if(receiverId){
       return res.status(200).send('please fill all the fields')
    }
        const newMessages = new Messages({ ConversationId: conversationId, SenderId: senderId, Message: message })
        await newMessages.save();
        res.status(200).send('Message sent successfully');

    } catch (error) {
        console.log(error, 'error');

    }
})
app.get('/api/message/:conversationId', async (req, res) => {
    try {
        const conversationId = req.params.conversationId;
        if(conversationId == 'new')
        return res.status(200).json([]);
        const messages = await Messages.find({ ConversationId: conversationId });
        console.log(messages);
        const messageUserData = Promise.all(messages.map(async (message) => {





            const user = await Users.findById(message.SenderId);
            if (user != null) {

                // console.log(user);
                console.log("email is" + user.email);

                return { user: { fullName: user.fullName, email: user.email }, message: message.Message }
            }
        }))


        res.status(200).json(await messageUserData);


    } catch (error) {
        console.log('error', error);

    }
})
app.get('/api/users', async(req,res) =>{
    try {
        const  users = await Users.find();
        const usersData = Promise.all(users.map(async (user) =>{
            return {users:{fullName:user.fullName, email:user.email}, userid: users._id}
        }))
        res.status(200).json( await usersData);
    } catch (error) {

        console.log('error', error);
        
    }
})

app.listen(port, () => {
    console.log(`server started on  ${port}`);

});