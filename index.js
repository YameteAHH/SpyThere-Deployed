import express from 'express';
import { initializeApp } from 'firebase/app';
import { getDatabase, ref, set, push, get, child, update, remove } from 'firebase/database';
import multer from 'multer';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import MemoryStore from 'memorystore';

// Create a memorystore session store
const MemoryStoreSession = MemoryStore(session);

// Load environment variables
dotenv.config();

// Get current directory for correct file paths in different environments
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Trust proxy for secure cookies in production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Session configuration with memorystore
app.use(session({
  store: new MemoryStoreSession({
    checkPeriod: 86400000, // Prune expired entries every 24h
    stale: false, // Don't delete stale sessions
    ttl: 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds
  }),
  secret: process.env.SESSION_SECRET || 'spythere-secret-key',
  resave: true, // Changed to true to ensure session is saved on every request
  saveUninitialized: false,
  rolling: true, // Reset cookie expiration on every response
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' // Use 'none' in production for cross-site requests
  }
}));

// Configure multer for handling file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    // Accept images, videos, and gifs
    if (file.mimetype.startsWith('image/') ||
      file.mimetype.startsWith('video/') ||
      file.mimetype === 'image/gif') {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images, videos, and GIFs are allowed.'));
    }
  }
});

// S3 Configuration - Use environment variables from .env file
const S3_CONFIG = {
  region: process.env.AWS_REGION || 'ap-southeast-2',
  bucketName: process.env.AWS_S3_BUCKET_NAME || 'spytherebucket',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
};

// Media upload handler
async function uploadFileToS3(file) {
  if (!file) return null;

  const fileExtension = file.originalname.split('.').pop();
  const key = `uploads/${uuidv4()}.${fileExtension}`;

  console.log(`Uploading file: ${file.originalname} (${file.size} bytes)`);
  console.log(`Using S3 config: region=${S3_CONFIG.region}, bucket=${S3_CONFIG.bucketName}`);
  console.log(`Using credentials: accessKeyId=${S3_CONFIG.accessKeyId.substring(0, 5)}...`);

  try {
    const s3Client = new S3Client({
      region: S3_CONFIG.region,
      credentials: {
        accessKeyId: S3_CONFIG.accessKeyId,
        secretAccessKey: S3_CONFIG.secretAccessKey
      },
      forcePathStyle: true // Use path-style URLs for better compatibility
    });

    // Log configuration details for debugging
    console.log(`S3 client configured with region: ${S3_CONFIG.region}`);
    console.log(`Using bucket: ${S3_CONFIG.bucketName}`);
    console.log(`Credentials loaded: ${!!S3_CONFIG.accessKeyId && !!S3_CONFIG.secretAccessKey}`);

    const uploadParams = {
      Bucket: S3_CONFIG.bucketName,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype,
      ACL: 'public-read' // Makes the file publicly accessible
    };

    console.log(`Uploading to S3 bucket: ${S3_CONFIG.bucketName} in region ${S3_CONFIG.region}`);
    const uploadResult = await s3Client.send(new PutObjectCommand(uploadParams));
    console.log('S3 upload successful!', uploadResult);

    // Construct the media URL based on region and bucket
    let mediaUrl;
    if (S3_CONFIG.region === 'us-east-1') {
      // US East 1 has a different URL format
      mediaUrl = `https://${S3_CONFIG.bucketName}.s3.amazonaws.com/${key}`;
    } else {
      // Standard URL format for all other regions
      mediaUrl = `https://${S3_CONFIG.bucketName}.s3.${S3_CONFIG.region}.amazonaws.com/${key}`;
    }
    console.log(`Media URL: ${mediaUrl}`);

    return mediaUrl;
  } catch (error) {
    console.error('S3 upload error:', error);

    // Enhanced error logging
    if (error.Code) console.error('AWS Error Code:', error.Code);
    if (error.message) console.error('Error message:', error.message);
    if (error.$metadata) {
      console.error('Error metadata:', JSON.stringify(error.$metadata));
      console.error('Request ID:', error.$metadata.requestId);
      console.error('HTTP Status Code:', error.$metadata.httpStatusCode);
    }

    throw new Error(`Failed to upload media: ${error.message}`);
  }
}

// Firebase configuration
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY || "AIzaSyD1lJAV3m3b0wAKPww8moPHl6dD8-Mgv4M",
  authDomain: process.env.FIREBASE_AUTH_DOMAIN || "spythere-8b6c7.firebaseapp.com",
  databaseURL: process.env.FIREBASE_DATABASE_URL || "https://spythere-8b6c7-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: process.env.FIREBASE_PROJECT_ID || "spythere-8b6c7",
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET || "spythere-8b6c7.firebasestorage.app",
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || "953650363803",
  appId: process.env.FIREBASE_APP_ID || "1:953650363803:web:ceaad94aeecb2e274a753e",
  measurementId: process.env.FIREBASE_MEASUREMENT_ID || "G-F57JK91PE2"
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const db = getDatabase(firebaseApp);
const postsRef = ref(db, 'posts');
const commentsRef = ref(db, 'comments');
const likesRef = ref(db, 'likes');

// Improved isAuthenticated function with better session validation
function isAuthenticated(req) {
  // Check for valid session
  if (req.session && req.session.user && req.session.user.username) {
    console.log(`User ${req.session.user.username} is authenticated via session`);
    return true;
  }

  console.log('Session validation failed');
  return false;
}

// More reliable authenticator middleware for all routes
function authenticator(req, res, next) {
  console.log(`Authentication check for ${req.path}`);
  console.log(`Session ID: ${req.session?.id || 'no session'}`);
  console.log(`Session cookie: ${req.session?.cookie ? 'exists' : 'missing'}`);
  console.log(`Has user object: ${!!(req.session && req.session.user)}`);

  try {
    if (req.session && req.session.user && req.session.user.username) {
      console.log(`User authenticated: ${req.session.user.username}`);

      // Extend session life
      try {
        req.session.touch();
        req.session._garbage = Date.now();
        req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));

        // For important operations, save the session immediately
        if (req.method === 'POST' || req.path.includes('/api/')) {
          req.session.save(err => {
            if (err) {
              console.error('Warning: Error saving session during authentication:', err);
              // Continue despite error to avoid breaking functionality
            }
          });
        }
      } catch (sessionError) {
        console.error('Error updating session in authenticator:', sessionError);
        // Continue despite error
      }

      next();
    } else {
      // For API requests, return JSON error
      if (req.path.startsWith('/api/') && !req.path.includes('/api/session-status')) {
        console.log('API authentication failed');
        return res.status(401).json({
          error: 'Authentication required',
          redirect: '/login'
        });
      }

      // For page requests, redirect to login
      console.log('Redirecting to login page');
      res.redirect('/login');
    }
  } catch (error) {
    console.error('Unexpected error in authenticator middleware:', error);
    // For API requests
    if (req.path.startsWith('/api/')) {
      return res.status(500).json({
        error: 'Authentication error',
        details: error.message
      });
    }
    // For page requests
    res.redirect('/login');
  }
}

// Routes
app.get('/', (req, res) => res.render('opening_page.ejs'));

app.get('/login', (req, res) => res.render('log_in.ejs', { error: null }));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt for email:', email);

  try {
    const sanitizedEmail = email.replace(/\./g, '_');
    console.log('Sanitized email for Firebase lookup:', sanitizedEmail);

    const userRef = child(ref(db, 'users'), sanitizedEmail);
    const snapshot = await get(userRef);
    console.log('User found in database:', snapshot.exists());

    if (snapshot.exists() && snapshot.val().password === password) {
      const userData = snapshot.val();
      console.log('Password verified for user:', userData.username);

      // Create a secure session token
      const sessionToken = uuidv4();

      // Store user data in session
      req.session.user = {
        email: email,
        username: userData.username,
        sessionToken: sessionToken
      };

      console.log('Session created with ID:', req.session.id);

      // Also set a backup cookie for additional authentication
      res.cookie('authToken', sessionToken, {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
      });

      // Explicitly save session before redirecting
      req.session.save((err) => {
        if (err) {
          console.error('Error saving session:', err);
          return res.status(500).render('log_in.ejs', { error: 'Session error: ' + err.message });
        }

        console.log('Session saved successfully, redirecting to /home');
        return res.redirect('/home');
      });
    } else {
      console.log('Login failed: Invalid credentials');
      res.render('log_in.ejs', { error: 'Invalid email or password' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).render('log_in.ejs', { error: 'Server error: ' + error.message });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Error destroying session:', err);
    res.redirect('/login');
  });
});

app.get('/signup', (req, res) => res.render('sign_up.ejs'));

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).send('All fields are required.');
  }
  try {
    const sanitizedEmail = email.replace(/\./g, '_');
    await set(child(ref(db, 'users'), sanitizedEmail), {
      username,
      email,
      password,
    });
    res.redirect('/login');
  } catch (error) {
    console.error('Sign up error:', error);
    res.status(500).send('Something went wrong.');
  }
});

app.get('/home', authenticator, async (req, res) => {
  try {
    console.log('Home page request for user:', req.session.user.username);

    const snapshot = await get(postsRef);
    let posts = [];
    if (snapshot.exists()) {
      const data = snapshot.val();
      console.log('Posts retrieved from Firebase:', Object.keys(data).length);

      posts = Object.entries(data).map(([id, value]) => ({
        id,
        value: value.post || value,
        username: value.username || 'Anonymous',
        mediaUrl: value.mediaUrl || null,
      })).reverse();
    } else {
      console.log('No posts found in database');
    }
    
    // Ensure every post has a valid ID for the comments API
    posts = posts.map(post => {
      if (!post.id) {
        console.warn('Post without ID detected, generating one');
        post.id = 'post-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
      }
      return post;
    });
    
    // Get username from session
    const username = req.session.user.username;
    const apiVersion = 1; // Increment this when API changes
    
    console.log('Rendering home page with', posts.length, 'posts for user', username);

    res.render('home_page.ejs', { 
      posts, 
      username: username,
      apiVersion: apiVersion
    });
  } catch (error) {
    console.error('Error loading home page:', error);
    console.error('Error stack:', error.stack);
    res.status(500).send('Error loading home page: ' + error.message);
  }
});

app.post('/submit-post', upload.single('media'), async (req, res) => {
  try {
    console.log('Starting post submission process');
    console.log('Session ID:', req.session?.id);
    console.log('Session user:', req.session?.user);

    // Check authentication
    if (!req.session || !req.session.user) {
      console.error('Session validation failed in submit-post');
      return res.status(401).json({
        error: 'Authentication required',
        redirect: '/login'
      });
    }

    const username = req.session.user.username;
    console.log(`Processing post submission from user: ${username}`);
    console.log('Request body:', req.body);
    console.log('File:', req.file ? `${req.file.originalname} (${req.file.size} bytes)` : 'No file uploaded');

    // Explicitly extend the session
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));

    // Save session before starting upload
    await new Promise((resolve, reject) => {
      req.session.save(err => {
        if (err) {
          console.error('Error saving session before media upload:', err);
          reject(err);
        } else {
          console.log('Session saved successfully before upload');
          resolve();
        }
      });
    });

    const post = req.body.post || '';
    let mediaUrl = null;

    // Upload media file to S3 if one was provided
    if (req.file) {
      try {
        mediaUrl = await uploadFileToS3(req.file);
        console.log('Media uploaded to S3:', mediaUrl);
      } catch (uploadError) {
        console.error('Media upload failed:', uploadError.message);
        return res.status(500).json({
          error: 'Media upload failed',
          details: uploadError.message
        });
      }
    }

    // Validate post content - require either text or media
    if (post.trim() === '' && !mediaUrl) {
      return res.status(400).json({
        error: 'Post content required',
        details: 'Please provide either text content or a media file'
      });
    }

    // Save post to Firebase
    console.log('Saving post to database...');
    const newPost = {
      post: post.trim(),
      username: username,
      mediaUrl: mediaUrl,
      timestamp: Date.now()
    };

    await push(postsRef, newPost);
    console.log('Post saved successfully');

    // Save the session again after the post has been saved
    await new Promise((resolve, reject) => {
      req.session.save(err => {
        if (err) {
          console.error('Error saving session after post creation:', err);
          reject(err);
        } else {
          console.log('Session saved successfully after post creation');
          resolve();
        }
      });
    });

    // Redirect or return success response
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      return res.status(200).json({ success: true, redirect: '/home' });
    } else {
      return res.redirect('/home');
    }
  } catch (error) {
    console.error('Error in post submission:', error);
    res.status(500).json({
      error: 'Error submitting post',
      details: error.message,
      stack: error.stack
    });
  }
});

app.get('/profile', authenticator, async (req, res) => {
  try {
    console.log(`Profile page requested by ${req.session.user.username}`);

    // Explicitly update and save session before database operations
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));
    await new Promise((resolve, reject) => {
      req.session.save(err => {
        if (err) {
          console.error('Error saving session before profile load:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    console.log('Session extended and saved for profile page');

    const snapshot = await get(postsRef);
    let posts = [];
    if (snapshot.exists()) {
      const data = snapshot.val();
      posts = Object.entries(data)
        .map(([id, value]) => ({
          id,
          value: value.post || value,
          username: value.username || 'Anonymous',
          mediaUrl: value.mediaUrl || null
        }))
        .filter(post => post.username === req.session.user.username)
        .reverse();

      console.log(`Found ${posts.length} posts for user profile`);
    }

    // Final session check before rendering
    if (!req.session.user) {
      console.error('Session lost during profile page load');
      return res.redirect('/login');
    }

    res.render('profile_page.ejs', {
      username: req.session.user.username,
      email: req.session.user.email,
      posts: posts 
    });
  } catch (error) {
    console.error('Error in profile page:', error);
    res.status(500).send('Error loading profile: ' + error.message);
  }
});

// Handle profile update
app.post('/update-profile', authenticator, async (req, res) => {
  try {
    const { username, email, currentPassword } = req.body;
    const oldUsername = req.session.user.username;
    
    // Verify current password
    const oldEmail = req.session.user.email;
    const sanitizedOldEmail = oldEmail.replace(/\./g, '_');
    const userRef = child(ref(db, 'users'), sanitizedOldEmail);
    const snapshot = await get(userRef);
    
    if (!snapshot.exists() || snapshot.val().password !== currentPassword) {
      return res.render('profile_page.ejs', { 
        username: req.session.user.username,
        email: req.session.user.email,
        posts: [],
        error: 'Invalid password. Changes not saved.'
      });
    }
    
    // Check if username changed and update all references
    if (username !== oldUsername) {
      console.log(`Updating username from ${oldUsername} to ${username}`);
      
      // Update username in all user's posts
      try {
        const postsSnapshot = await get(postsRef);
        if (postsSnapshot.exists()) {
          const allPosts = postsSnapshot.val();
          
          // Iterate through all posts
          for (const postId in allPosts) {
            const post = allPosts[postId];
            if (post.username === oldUsername) {
              console.log(`Updating post ${postId}`);
              await update(ref(db, `posts/${postId}`), { username: username });
            }
          }
        }
      } catch (postError) {
        console.error('Error updating posts:', postError);
        // Don't stop the process for post update errors
      }
      
      // Update username in all comments
      try {
        const commentsSnapshot = await get(commentsRef);
        if (commentsSnapshot.exists()) {
          const allComments = commentsSnapshot.val();
          
          // Iterate through all post comments
          for (const postId in allComments) {
            const postComments = allComments[postId];
            
            // Update author field in each comment by this user
            for (const commentId in postComments) {
              const comment = postComments[commentId];
              if (comment.author === oldUsername) {
                console.log(`Updating comment ${commentId} in post ${postId}`);
                await update(ref(db, `comments/${postId}/${commentId}`), { author: username });
              }
            }
          }
        }
      } catch (commentError) {
        console.error('Error updating comments:', commentError);
        // Don't stop the process for comment update errors
      }
      
      // Update username in all likes
      try {
        const likesSnapshot = await get(likesRef);
        if (likesSnapshot.exists()) {
          const allLikes = likesSnapshot.val();
          
          // Iterate through all post likes
          for (const postId in allLikes) {
            const postLikes = allLikes[postId];
            
            // The user's like entry is stored with sanitized username as key
            const sanitizedOldUsername = oldUsername.replace(/\./g, '_');
            if (postLikes[sanitizedOldUsername]) {
              console.log(`Updating like in post ${postId}`);
              
              // Get the like data
              const likeData = postLikes[sanitizedOldUsername];
              
              // Create new entry with new username
              const sanitizedNewUsername = username.replace(/\./g, '_');
              await set(ref(db, `likes/${postId}/${sanitizedNewUsername}`), {
                ...likeData,
                username: username // Update the username field
              });
              
              // Remove old entry
              await remove(ref(db, `likes/${postId}/${sanitizedOldUsername}`));
            }
          }
        }
      } catch (likeError) {
        console.error('Error updating likes:', likeError);
        // Don't stop the process for like update errors
      }
    }
    
    // Create updated user data
    const updatedUser = {
      username,
      email,
      password: snapshot.val().password // Keep existing password
    };
    
    // If email changed, delete old record and create new one
    if (email !== oldEmail) {
      // Create new user record with new email
      const sanitizedNewEmail = email.replace(/\./g, '_');
      const newUserRef = child(ref(db, 'users'), sanitizedNewEmail);
      
      // Check if new email already exists
      const newEmailSnapshot = await get(newUserRef);
      if (newEmailSnapshot.exists()) {
        return res.render('profile_page.ejs', { 
          username: req.session.user.username,
          email: req.session.user.email,
          posts: [],
          error: 'Email already exists. Please choose a different one.'
        });
      }
      
      // Add new record
      await set(newUserRef, updatedUser);
      
      // Delete old record
      await remove(userRef);
      
      // Update session data
      req.session.user.email = email;
      req.session.user.username = username;
      
      // Redirect to updated profile page with success message
      return res.render('profile_page.ejs', { 
        username: username, 
        email: email,
        posts: [], // Will be populated on next page load
        success: 'Profile updated successfully!'
      });
    } 
    
    // If only username changed, update existing record
    await update(userRef, { username });
    
    // Update session
    req.session.user.username = username;
    
    // Redirect to updated profile page with success message
    return res.render('profile_page.ejs', { 
      username: username, 
      email: email,
      posts: [], // Will be populated on next page load
      success: 'Profile updated successfully!'
    });
    
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).render('profile_page.ejs', { 
      username: req.session.user.username,
      email: req.session.user.email,
      posts: [],
      error: 'Error updating profile: ' + error.message
    });
  }
});

app.get('/api/username', (req, res) => {
  if (req.session && req.session.user) {
    // Touch the session to keep it alive
    req.session.touch();

    res.json({ username: req.session.user.username });
  } else {
    res.status(401).json({
      error: 'Not authenticated',
      redirect: '/login'
    });
  }
});

// Comment API Routes
app.post('/api/comments', authenticator, async (req, res) => {
  try {
    const { postId, text } = req.body;
    console.log(`Comment submission by ${req.session.user.username} for post ${postId}`);
    
    if (!postId || !text || text.trim() === '') {
      return res.status(400).json({ error: 'Post ID and comment text are required' });
    }

    const decodedPostId = decodeURIComponent(postId);
    
    const newComment = {
      postId: decodedPostId,
      text: text.trim(),
      author: req.session.user.username,
      timestamp: Date.now()
    };

    // Create a reference to the specific post's comments collection
    const postCommentsRef = ref(db, `comments/${decodedPostId}`);
    const newCommentRef = push(postCommentsRef);

    await set(newCommentRef, newComment);
    console.log('Comment saved successfully');
    
    // Extend session
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));
    req.session.save();

    res.status(201).json({ 
      id: newCommentRef.key,
      ...newComment
    });
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ error: 'Failed to add comment: ' + error.message });
  }
});

app.get('/api/comments/:postId', async (req, res) => {
  try {
    const { postId } = req.params;
    console.log('Fetching comments for post:', postId);
    
    if (!postId) {
      return res.status(400).json({ error: 'Post ID is required' });
    }
    
    // Decode the postId if it was URL encoded
    const decodedPostId = decodeURIComponent(postId);
    console.log('Decoded post ID:', decodedPostId);
    
    const postCommentsRef = ref(db, `comments/${decodedPostId}`);
    const snapshot = await get(postCommentsRef);
    
    let comments = [];
    if (snapshot.exists()) {
      const data = snapshot.val();
      comments = Object.entries(data).map(([id, comment]) => ({
        id,
        ...comment
      })).sort((a, b) => b.timestamp - a.timestamp); // Sort newest first
      
      console.log(`Found ${comments.length} comments for post ${decodedPostId}`);
    } else {
      console.log(`No comments found for post ${decodedPostId}`);
    }
    
    // If user is authenticated, refresh their session
    if (req.session && req.session.user) {
      req.session.touch();
    }

    res.json({ comments });
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ error: 'Failed to fetch comments: ' + error.message });
  }
});

// Update a comment
app.put('/api/comments/:postId/:commentId', authenticator, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    const { text } = req.body;
    
    console.log(`Updating comment ${commentId} by ${req.session.user.username}`);
    
    if (!postId || !commentId) {
      return res.status(400).json({ error: 'Post ID and Comment ID are required' });
    }
    
    if (!text || text.trim() === '') {
      return res.status(400).json({ error: 'Comment text is required' });
    }
    
    // Decode IDs if they were URL encoded
    const decodedPostId = decodeURIComponent(postId);
    const decodedCommentId = decodeURIComponent(commentId);
    
    // Get the comment to check ownership
    const commentRef = ref(db, `comments/${decodedPostId}/${decodedCommentId}`);
    const snapshot = await get(commentRef);
    
    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    
    const comment = snapshot.val();
    
    // Check if the current user is the author of the comment
    if (comment.author !== req.session.user.username) {
      return res.status(403).json({ error: 'You can only edit your own comments' });
    }
    
    // Update the comment
    await update(commentRef, {
      text: text.trim(),
      edited: true,
      editTimestamp: Date.now()
    });
    
    // Get the updated comment
    const updatedSnapshot = await get(commentRef);
    const updatedComment = {
      id: decodedCommentId,
      ...updatedSnapshot.val()
    };
    
    console.log('Comment updated successfully');
    
    // Extend session
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));
    req.session.save();

    res.json(updatedComment);
  } catch (error) {
    console.error('Error updating comment:', error);
    res.status(500).json({ error: 'Failed to update comment: ' + error.message });
  }
});

// Delete a comment
app.delete('/api/comments/:postId/:commentId', authenticator, async (req, res) => {
  try {
    const { postId, commentId } = req.params;
    
    console.log(`Deleting comment ${commentId} by ${req.session.user.username}`);
    
    if (!postId || !commentId) {
      return res.status(400).json({ error: 'Post ID and Comment ID are required' });
    }
    
    // Decode IDs if they were URL encoded
    const decodedPostId = decodeURIComponent(postId);
    const decodedCommentId = decodeURIComponent(commentId);
    
    // Get the comment to check ownership
    const commentRef = ref(db, `comments/${decodedPostId}/${decodedCommentId}`);
    const snapshot = await get(commentRef);
    
    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    
    const comment = snapshot.val();
    
    // Check if the current user is the author of the comment
    if (comment.author !== req.session.user.username) {
      return res.status(403).json({ error: 'You can only delete your own comments' });
    }
    
    // Delete the comment
    await remove(commentRef);
    
    console.log('Comment deleted successfully');
    
    // Extend session
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));
    req.session.save();

    res.json({ success: true, message: 'Comment deleted successfully' });
  } catch (error) {
    console.error('Error deleting comment:', error);
    res.status(500).json({ error: 'Failed to delete comment: ' + error.message });
  }
});

// Like API Routes
app.post('/api/likes', authenticator, async (req, res) => {
  try {
    const { postId, liked } = req.body;
    console.log(`Like action by ${req.session.user.username} for post ${postId}: ${liked}`);
    
    if (!postId) {
      return res.status(400).json({ error: 'Post ID is required' });
    }

    const decodedPostId = decodeURIComponent(postId);
    
    // Create a unique ID for this user's like on this post
    const username = req.session.user.username;
    const userLikeId = username.replace(/\./g, '_'); // Sanitize the username for Firebase
    
    // Reference to this specific user's like for this post
    const userLikeRef = ref(db, `likes/${decodedPostId}/${userLikeId}`);
    
    if (liked) {
      // Add the like
      await set(userLikeRef, {
        username: username,
        timestamp: Date.now()
      });
    } else {
      // Remove the like
      await remove(userLikeRef);
    }
    
    // Get updated like count
    const postLikesRef = ref(db, `likes/${decodedPostId}`);
    const snapshot = await get(postLikesRef);
    const likeCount = snapshot.exists() ? Object.keys(snapshot.val()).length : 0;
    
    // Extend session
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));

    // Explicitly save the session and wait for completion
    await new Promise((resolve, reject) => {
      req.session.save(err => {
        if (err) {
          console.error('Error saving session after like action:', err);
          reject(err);
        } else {
          console.log('Session saved successfully after like action');
          resolve();
        }
      });
    });

    res.json({ 
      success: true,
      liked: liked,
      likeCount: likeCount
    });
  } catch (error) {
    console.error('Error updating like:', error);
    res.status(500).json({ error: 'Failed to update like: ' + error.message });
  }
});

app.get('/api/likes/:postId', async (req, res) => {
  try {
    const { postId } = req.params;
    console.log('Fetching likes for post:', postId);
    
    if (!postId) {
      return res.status(400).json({ error: 'Post ID is required' });
    }
    
    // Decode the postId if it was URL encoded
    const decodedPostId = decodeURIComponent(postId);
    console.log('Decoded post ID:', decodedPostId);
    
    const postLikesRef = ref(db, `likes/${decodedPostId}`);
    const snapshot = await get(postLikesRef);
    
    let likes = [];
    let userLiked = false;
    
    if (snapshot.exists()) {
      const data = snapshot.val();
      likes = Object.entries(data).map(([id, like]) => ({
        id,
        username: like.username,
        timestamp: like.timestamp
      }));
      
      // Check if current user has liked this post
      if (req.session && req.session.user) {
        const username = req.session.user.username;
        const userLikeId = username.replace(/\./g, '_');
        userLiked = data[userLikeId] !== undefined;

        // Touch the session to keep it alive
        req.session.touch();
      }
      
      console.log(`Found ${likes.length} likes for post ${decodedPostId}`);
    } else {
      console.log(`No likes found for post ${decodedPostId}`);
    }
    
    res.json({ 
      likes,
      userLiked
    });
  } catch (error) {
    console.error('Error fetching likes:', error);
    res.status(500).json({ error: 'Failed to fetch likes: ' + error.message });
  }
});

// Post API Routes
app.put('/api/posts/:postId', authenticator, async (req, res) => {
  try {
    const { postId } = req.params;
    const { value } = req.body;

    console.log(`Updating post ${postId} by ${req.session.user.username}`);

    if (!postId) {
      return res.status(400).json({ error: 'Post ID is required' });
    }

    if (!value || value.trim() === '') {
      return res.status(400).json({ error: 'Post content is required' });
    }

    // Decode the postId if it was URL encoded
    const decodedPostId = decodeURIComponent(postId);

    // Get the post to check ownership
    const postRef = ref(db, `posts/${decodedPostId}`);
    const snapshot = await get(postRef);

    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const post = snapshot.val();

    // Check if the current user is the author of the post
    if (post.username !== req.session.user.username) {
      return res.status(403).json({ error: 'You can only edit your own posts' });
    }

    // Update the post
    await update(postRef, {
      post: value.trim(),
      edited: true,
      editTimestamp: Date.now(),
      mediaUrl: post.mediaUrl // Preserve the mediaUrl field
    });

    // Get the updated post
    const updatedSnapshot = await get(postRef);
    const updatedPost = {
      id: decodedPostId,
      value: updatedSnapshot.val().post,
      username: updatedSnapshot.val().username,
      mediaUrl: updatedSnapshot.val().mediaUrl
    };

    console.log('Post updated successfully');

    // Extend session
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));
    req.session.save();

    res.json(updatedPost);
  } catch (error) {
    console.error('Error updating post:', error);
    res.status(500).json({ error: 'Failed to update post: ' + error.message });
  }
});

// Delete a post
app.delete('/api/posts/:postId', authenticator, async (req, res) => {
  try {
    const { postId } = req.params;

    console.log(`Deleting post ${postId} by ${req.session.user.username}`);

    if (!postId) {
      return res.status(400).json({ error: 'Post ID is required' });
    }

    // Decode the postId if it was URL encoded
    const decodedPostId = decodeURIComponent(postId);

    // Get the post to check ownership
    const postRef = ref(db, `posts/${decodedPostId}`);
    const snapshot = await get(postRef);

    if (!snapshot.exists()) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const post = snapshot.val();

    // Check if the current user is the author of the post
    if (post.username !== req.session.user.username) {
      return res.status(403).json({ error: 'You can only delete your own posts' });
    }

    // Delete the post
    await remove(postRef);

    // Also delete all comments and likes for this post
    const postCommentsRef = ref(db, `comments/${decodedPostId}`);
    const postLikesRef = ref(db, `likes/${decodedPostId}`);

    await remove(postCommentsRef);
    await remove(postLikesRef);

    console.log('Post and associated data deleted successfully');

    // Extend session
    req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));
    req.session.save();

    res.json({ success: true, message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Error deleting post:', error);
    res.status(500).json({ error: 'Failed to delete post: ' + error.message });
  }
});

// Add a route to validate session status
app.get('/api/session-status', (req, res) => {
  console.log('Session status check');
  console.log('Session ID:', req.session?.id);
  console.log('Session cookie:', req.session?.cookie);
  console.log('User object:', req.session?.user);

  if (req.session && req.session.user) {
    // Touch the session to keep it alive
    try {
      req.session.touch();
      req.session.cookie.expires = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000));
      req.session.save(err => {
        if (err) {
          console.error('Error saving session during status check:', err);
        }
      });
    } catch (sessionError) {
      console.error('Error updating session in status check:', sessionError);
    }

    // Return user info without sensitive data
    res.json({
      authenticated: true,
      username: req.session.user.username,
      sessionId: req.session.id,
      cookieMaxAge: req.session.cookie.maxAge,
      cookieExpires: req.session.cookie.expires,
      secure: req.session.cookie.secure,
      sameSite: req.session.cookie.sameSite
    });
  } else {
    // Not authenticated
    res.json({
      authenticated: false,
      message: 'User not authenticated',
      sessionExists: !!req.session,
      cookieHeader: req.headers.cookie ? 'Present' : 'Missing'
    });
  }
});

// If this file is executed directly (not imported), start the server
// The previous condition might not work reliably on Windows
// if (import.meta.url === `file://${process.argv[1]}`) {

// Always start the server when this file is run directly
const server = app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`To view the app, open a browser and navigate to http://localhost:${port}`);

  // Log environment status
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`AWS Region: ${process.env.AWS_REGION || 'not set'}`);
  console.log(`S3 Bucket: ${process.env.AWS_S3_BUCKET_NAME || 'not set'}`);
  console.log(`AWS Credentials loaded: ${!!process.env.AWS_ACCESS_KEY_ID && !!process.env.AWS_SECRET_ACCESS_KEY}`);
});

// For clean shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});

export { app };
