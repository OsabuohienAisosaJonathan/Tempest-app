const mongoose = require('mongoose');
const { isEmail } = require('validator');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  // ident: {
  //   type: mongoose.Decimal128
  // },
  name: {
    type: String,
    required: [true, 'Please enter your Fullname'],
    lowercase: true
  },
  address: {
    type: String,
    required: [true, 'Please enter your address'],
    lowercase: true
  },
  wnumber: {
    type: String,
    required: [true, 'Please enter your whatsapp number'],
    lowercase: true
  },
  socials: {
    type: String,
    required: [true, 'Please enter any of your social media handle here']
  },
  email: {
    type: String,
    required: [true, 'Please enter an email'],
    unique: true,
    lowercase: true,
    validate: [isEmail, 'Please enter a valid email']
  },
  occupation: {
    type: String,
    required: [true, 'Please enter your occupation']
  },
  stateOfOrigin: {
    type: String,
    required: [true, 'Please enter your state of origin']
  },
  lga: {
    type: String,
    required: [true, 'Please enter your Local Government Area'],
    lowercase: true
  },
  DOB: {
    type: String,
    lowercase: true,
    required: [true, 'Please enter your Date of Birth']
  },
  password: {
    type: String,
    required: [true, 'Please enter a password'],
    minlength: [8, 'Minimum password length is 8 characters'],
  },
  gradYear: {
    type: String,
    lowercase: true,
    required: [true, 'Please enter your graduationn year']
  }
});


// fire a function before doc saved to db
userSchema.pre('save', async function(next) {
  const salt = await bcrypt.genSalt();
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// static method to login user
userSchema.statics.login = async function(email, password) {
  const user = await this.findOne({ email });
  if (user) {
    const auth = await bcrypt.compare(password, user.password);
    if (auth) {
      return user;
    }
    throw Error('incorrect password');
  }
  throw Error('incorrect email');
};

const User = mongoose.model('user', userSchema);

module.exports = User;