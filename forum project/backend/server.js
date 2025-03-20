// server.js

const express = require('express');
const bodyParser = require('body-parser');
const { ethers } = require('ethers'); // For signature verification
const cors = require('cors');
const uuid = require('uuid'); // To create unique IDs for posts and sessions

const app = express();
const port = 3000;

// Middleware to parse JSON and enable CORS for testing
app.use(bodyParser.json());
app.use(cors());

// --- In-memory data stores ---
// For demonstration only. In a real app, use a persistent database.
let users = {};    // key: walletAddress, value: nonce for login
let sessions = {}; // key: session token, value: walletAddress
let posts = [];    // Array of posts

// A post object structure:
// {
//   id: <unique id>,
//   author: <wallet address>,
//   content: <post content>,
//   upvotes: <number>,
//   downvotes: <number>,
//   replies: [
//     { id: <unique id>, author: <wallet address>, content: <reply content> }
//   ]
// }

// --- Authentication Endpoints ---

// Request a nonce for login. The client sends its wallet address.
app.post('/auth/request_nonce', (req, res) => {
  const { walletAddress } = req.body;
  if (!walletAddress) {
    return res.status(400).json({ error: 'Missing walletAddress' });
  }
  // Generate a random nonce (a number converted to string)
  const nonce = Math.floor(Math.random() * 1000000).toString();
  // Save the nonce associated with this wallet address
  users[walletAddress.toLowerCase()] = nonce;
  res.json({ nonce });
});

// Verify the signed nonce. The client sends back the wallet address and signature.
app.post('/auth/verify', (req, res) => {
  const { walletAddress, signature } = req.body;
  if (!walletAddress || !signature) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  // Get the previously stored nonce
  const nonce = users[walletAddress.toLowerCase()];
  if (!nonce) {
    return res.status(400).json({ error: 'No nonce found, request a nonce first.' });
  }
  // The message that was signed (must match the client’s signing request)
  const message = `Login nonce: ${nonce}`;
  try {
    // Recover the address from the signature
    const recoveredAddress = ethers.utils.verifyMessage(message, signature);
    if (recoveredAddress.toLowerCase() === walletAddress.toLowerCase()) {
      // Signature is valid—create a session token
      const token = uuid.v4();
      sessions[token] = walletAddress.toLowerCase();
      // Remove the nonce now that it’s been used
      delete users[walletAddress.toLowerCase()];
      return res.json({ token });
    } else {
      return res.status(401).json({ error: 'Signature verification failed' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'Error verifying signature' });
  }
});

// Middleware to authenticate requests using a token provided in the header
function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.walletAddress = sessions[token];
  next();
}

// --- Forum Endpoints ---

// Create a new post (requires authentication)
app.post('/posts', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'Missing content' });
  }
  const newPost = {
    id: uuid.v4(),
    author: req.walletAddress,
    content,
    upvotes: 0,
    downvotes: 0,
    replies: []
  };
  posts.push(newPost);
  res.json({ post: newPost });
});

// Reply to a post (requires authentication)
app.post('/posts/:postId/replies', authMiddleware, (req, res) => {
  const { content } = req.body;
  const { postId } = req.params;
  if (!content) {
    return res.status(400).json({ error: 'Missing content' });
  }
  const post = posts.find(p => p.id === postId);
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  const reply = {
    id: uuid.v4(),
    author: req.walletAddress,
    content
  };
  post.replies.push(reply);
  res.json({ reply });
});

// Upvote a post (requires authentication)
app.post('/posts/:postId/upvote', authMiddleware, (req, res) => {
  const { postId } = req.params;
  const post = posts.find(p => p.id === postId);
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  post.upvotes += 1;
  res.json({ post });
});

// Downvote a post (requires authentication)
app.post('/posts/:postId/downvote', authMiddleware, (req, res) => {
  const { postId } = req.params;
  const post = posts.find(p => p.id === postId);
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  post.downvotes += 1;
  res.json({ post });
});

// Get all posts (publicly accessible)
app.get('/posts', (req, res) => {
  res.json({ posts });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
