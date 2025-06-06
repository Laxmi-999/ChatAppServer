require('dotenv').config(); // Load .env variables
const mongoose = require('mongoose');

async function main() {
  try {
    await mongoose.connect(process.env.MONGODB_URL);
    console.log('Database connected');
  } catch (error) {
    console.error('Error connecting to database:', error);
    process.exit(1);
  }
}

main().catch(err => console.error(err));
