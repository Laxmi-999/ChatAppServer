const mongoose = require('mongoose');


async function main() {
    try {
      await mongoose.connect('mongodb://127.0.0.1:27017/ChatApp');
      console.log('Database connected');
    } 
    catch (error) {
      console.error('Error connecting to database:', error);
      process.exit(1); // Exit the process if unable to connect to the database
    }
  }
  main().catch(err => console.error(err));