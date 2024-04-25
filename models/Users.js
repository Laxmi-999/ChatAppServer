const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    fullName: {
        type:String,
        require: true
    },
    email:{
        type: String,
        require: true,
        unique: true
    },
    password:{
        type: String,
        require:true
    },
    token:{
        type: String
    }

})

// defining models

const Users = mongoose.model('User', UserSchema);

module.exports = Users;