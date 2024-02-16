// Import modules
import { db } from '$lib/db.js'; // MongoDB connection
import bcrypt from 'bcrypt'; // Password hashing
import jwt from 'jsonwebtoken'; // JSON Web Token
import { createRequire } from 'sveltekit-adapter-node'; // Node.js require
const require = createRequire(import.meta.url); // Create require function
const { config } = require('dotenv'); // Load environment variables
config(); // Invoke config function

// Define constants
const SECRET = process.env.SECRET; // JWT secret
const SALT_ROUNDS = 10; // Bcrypt salt rounds

// Define helper functions
// Generate a JWT for a user
const generateToken = (user) => {
  return jwt.sign({ id: user._id, email: user.email }, SECRET, {
    expiresIn: '1h',
  });
};

// Verify a JWT and return the user data
const verifyToken = (token) => {
  try {
    return jwt.verify(token, SECRET);
  } catch (error) {
    return null;
  }
};

// Hash a password using bcrypt
const hashPassword = async (password) => {
  return await bcrypt.hash(password, SALT_ROUNDS);
};

// Compare a password with a hashed password using bcrypt
const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Define API endpoints
// Register a new user
export const post = async (request) => {
  // Get the user data from the request body
  const { email, password } = request.body;

  // Validate the user data
  if (!email || !password) {
    return {
      status: 400,
      body: { message: 'Email and password are required' },
    };
  }

  // Check if the user already exists
  const existingUser = await db.collection('users').findOne({ email });
  if (existingUser) {
    return {
      status: 409,
      body: { message: 'User already exists' },
    };
  }

  // Hash the password
  const hashedPassword = await hashPassword(password);

  // Create the user document
  const user = {
    email,
    password: hashedPassword,
  };

  // Insert the user into the database
  await db.collection('users').insertOne(user);

  // Generate a token for the user
  const token = generateToken(user);

  // Return the token as a response
  return {
    status: 201,
    body: { token },
  };
};

// Login an existing user
export const put = async (request) => {
  // Get the user data from the request body
  const { email, password } = request.body;

  // Validate the user data
  if (!email || !password) {
    return {
      status: 400,
      body: { message: 'Email and password are required' },
    };
  }

  // Find the user in the database
  const user = await db.collection('users').findOne({ email });
  if (!user) {
    return {
      status: 404,
      body: { message: 'User not found' },
    };
  }

  // Compare the password with the hashed password
  const match = await comparePassword(password, user.password);
  if (!match) {
    return {
      status: 401,
      body: { message: 'Invalid password' },
    };
  }

  // Generate a token for the user
  const token = generateToken(user);

  // Return the token as a response
  return {
    status: 200,
    body: { token },
  };
};

// Get the user profile
export const get = async (request) => {
  // Get the authorization header from the request
  const authHeader = request.headers.get('authorization');

  // Validate the authorization header
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      status: 401,
      body: { message: 'Unauthorized' },
    };
  }

  // Get the token from the authorization header
  const token = authHeader.split(' ')[1];

  // Verify the token and get the user data
  const user = verifyToken(token);
  if (!user) {
    return {
      status: 401,
      body: { message: 'Invalid token' },
    };
  }

  // Return the user data as a response
  return {
    status: 200,
    body: { user },
  };
};
