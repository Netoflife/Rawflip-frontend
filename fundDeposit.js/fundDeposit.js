// fundDeposit.js
require('dotenv').config();
const mongoose = require('mongoose');

// Use environment variables
const MONGO_URI = process.env.MONGO_URI;
const FUND_AMOUNT = Number(process.env.FUND_AMOUNT || 0);
const USERS_TO_FUND = ['Zaca', 'Netizen', 'Joy']; // usernames

if (!MONGO_URI) {
  console.error("MONGO_URI not set in environment");
  process.exit(1);
}

if (!FUND_AMOUNT) {
  console.error("FUND_AMOUNT not set or zero");
  process.exit(1);
}

// Define minimal User schema for deposit update
const userSchema = new mongoose.Schema({
  username: String,
  balance: Number,
});

const User = mongoose.model('User', userSchema);

(async () => {
  try {
    await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log("Connected to MongoDB");

    for (const username of USERS_TO_FUND) {
      const user = await User.findOne({ username });
      if (!user) {
        console.log(`User ${username} not found`);
        continue;
      }
      user.balance = (user.balance || 0) + FUND_AMOUNT;
      await user.save();
      console.log(`Funded ${FUND_AMOUNT} to ${username}. New balance: ${user.balance}`);
    }

    console.log("All done");
    process.exit(0);
  } catch (err) {
    console.error("Error funding users:", err);
    process.exit(1);
  }
})();
