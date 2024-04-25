const mongoose = require('mongoose');

const ConversationSchema = new mongoose.Schema({
    // here we store the user id who is logged in and user id with we just have converstion 
    Members: {
        type:Array,
        require: true
    },
});

// defining models

const Conversation = mongoose.model('Conversation', ConversationSchema);

module.exports = Conversation;