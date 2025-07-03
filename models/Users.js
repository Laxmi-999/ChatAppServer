const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    fullName: {
        type:String,
        required: true
    },
    email:{
        type: String,
        required: true,
        unique: true
    },
    password:{
        type: String,
        required:true,
        select:false
    },
    token:{
        type: String
    }

})

// defining models

const Users = mongoose.model('User', UserSchema, 'Users');

module.exports = Users;