# SpyThere App - Vercel Deployment Guide

This guide will help you deploy the SpyThere application to Vercel with all its features properly configured.

## Prerequisites

- A [Vercel](https://vercel.com) account
- Your SpyThere code repository on GitHub, GitLab, or Bitbucket
- Firebase project with Realtime Database and Authentication
- AWS S3 bucket

## Step 1: Prepare Your Environment Variables

Create a `.env` file locally with the following variables:

```
# Firebase Configuration
FIREBASE_API_KEY=your-api-key
FIREBASE_AUTH_DOMAIN=your-auth-domain
FIREBASE_DATABASE_URL=your-database-url
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_STORAGE_BUCKET=your-storage-bucket
FIREBASE_MESSAGING_SENDER_ID=your-messaging-sender-id
FIREBASE_APP_ID=your-app-id
FIREBASE_MEASUREMENT_ID=your-measurement-id

# AWS S3 Configuration
AWS_REGION=ap-southeast-2
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
S3_BUCKET_NAME=spytherebucket

# Server Configuration
PORT=3000
```

## Step 2: Configure Firebase

### Authentication
1. In your Firebase console, go to Authentication > Sign-in method
2. Enable Email/Password authentication
3. Add your Vercel domain to the Authorized domains list

### Realtime Database
1. Go to Realtime Database > Rules
2. Configure rules to allow read/write access from your Vercel domain:
```json
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
```
Note: For production, configure more restrictive rules based on authentication.

## Step 3: Configure AWS S3

1. In your AWS S3 console, select your bucket
2. Go to Permissions > CORS configuration
3. Add the following configuration:
```json
[
  {
    "AllowedHeaders": ["*"],
    "AllowedMethods": ["GET", "PUT", "POST", "DELETE", "HEAD"],
    "AllowedOrigins": ["*"],
    "ExposeHeaders": []
  }
]
```
4. For production, replace `"*"` in `"AllowedOrigins"` with your Vercel domain.

## Step 4: Configure Your Vercel Setup

### File Structure for Vercel

Vercel requires serverless functions to be in an `api` directory. Make sure your project has:

1. A main `index.js` file that exports your Express app:
```javascript
// At the end of your main index.js
export { app };
```

2. An `api/index.js` file that imports and uses the app:
```javascript
import { app } from '../index.js';

export default app;
```

### Update vercel.json

Make sure your vercel.json contains the following configuration to properly include EJS views:

```json
{
  "version": 2,
  "buildCommand": "npm install",
  "outputDirectory": ".",
  "functions": {
    "api/index.js": {
      "includeFiles": "views/**"
    }
  },
  "routes": [
    {
      "src": "/(.*)",
      "dest": "/api"
    }
  ]
}
```

### Update index.js

Make sure your index.js uses the correct path resolution for the views and static directories:

```javascript
import path from 'path';
import { fileURLToPath } from 'url';

// Get current directory for correct file paths in different environments
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
```

## Step 5: Deploy to Vercel

### Using the Vercel Dashboard

1. Log in to your Vercel dashboard
2. Click "New Project"
3. Import your GitHub/GitLab/Bitbucket repository
4. Configure the project:
   - Framework Preset: Choose "Other"
   - Build Command: `npm run vercel-build`
   - Output Directory: `.`
   - Install Command: `npm install`
5. Add Environment Variables:
   - Copy all variables from your `.env` file to the Environment Variables section
6. Click "Deploy"

### Using Vercel CLI

1. Install Vercel CLI:
```bash
npm install -g vercel
```

2. Log in to Vercel:
```bash
vercel login
```

3. Deploy from your project directory:
```bash
vercel
```

4. During the deployment process, you'll be prompted to add your environment variables.

## Troubleshooting

### Views Directory Not Found
If you see an error like "Failed to lookup view in views directory":
1. Make sure your vercel.json includes the "includeFiles" directive 
2. Make sure you're using the correct path resolution in index.js
3. Try redeploying after making these changes

### CORS Issues
If you encounter CORS errors:
1. Make sure your S3 bucket has the correct CORS configuration
2. Verify that Firebase has your Vercel domain listed in authorized domains

### Environment Variables
If your app can't connect to Firebase or AWS:
1. Check the environment variables in your Vercel project settings
2. Verify that they are correctly formatted

### EJS Templates
If your EJS templates aren't rendering:
1. Verify that the templates are correctly located in the `/views` directory
2. Check that static assets are properly loaded from the `/public` directory

### Session Management
If users are having trouble staying logged in:
1. Make sure the session management in `index.js` is working with Vercel's serverless environment

## Additional Resources

- [Vercel Documentation](https://vercel.com/docs)
- [Firebase Documentation](https://firebase.google.com/docs)
- [AWS S3 Documentation](https://docs.aws.amazon.com/s3/) 