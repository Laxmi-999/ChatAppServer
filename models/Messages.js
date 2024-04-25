const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
    // here we store the user id who is logged in and user id with we just have converstion 
    ConversationId: {
        type:String,
        require: true
    },
    SenderId:{
        type:String
    },

    Message:{
        type:String
    }


});

// defining models

const Message = mongoose.model('Message', MessageSchema);

module.exports = Message;