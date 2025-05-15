# SpyThere

A simple social media web application built with Express and Firebase.

## Features

- User authentication (signup/login)
- Post creation and viewing
- User profiles
- Real-time updates

## Setup

1. Clone the repository
2. Install dependencies: `npm install`
3. Start the server: `npm run serve`
4. Open `http://localhost:3000` in your browser

## Technology Stack

- Node.js with Express
- Firebase Realtime Database
- EJS templating
- Vanilla JavaScript 

## Vercel Deployment Guide

### Prerequisites
- Vercel account
- GitHub repository with your SpyThere code

### Environment Variables
When deploying to Vercel, make sure to add the following environment variables:

**Firebase Configuration:**
- FIREBASE_API_KEY
- FIREBASE_AUTH_DOMAIN
- FIREBASE_DATABASE_URL
- FIREBASE_PROJECT_ID
- FIREBASE_STORAGE_BUCKET
- FIREBASE_MESSAGING_SENDER_ID
- FIREBASE_APP_ID
- FIREBASE_MEASUREMENT_ID

**AWS S3 Configuration:**
- AWS_REGION
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- S3_BUCKET_NAME

**Server Configuration:**
- PORT (Optional, Vercel will assign its own port)

### Deployment Steps
1. Push your code to GitHub
2. Log in to Vercel and create a new project
3. Import your GitHub repository
4. Configure the environment variables in the Vercel dashboard
5. Deploy your application

### Important Notes
- Vercel automatically handles EJS templates
- Make sure your AWS S3 bucket CORS settings allow access from your Vercel domain
- Firebase security rules should be configured to allow your Vercel domain

### Local Development
```bash
npm install
npm run dev
``` 
"# Spider" 
"# SpyThere-Deployed" 
