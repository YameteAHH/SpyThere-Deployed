import { S3Client, ListBucketsCommand } from '@aws-sdk/client-s3';
import dotenv from 'dotenv';
import { initializeApp } from 'firebase/app';
import { getDatabase, ref, get } from 'firebase/database';

// Load environment variables
dotenv.config();

console.log('Starting health check...');
console.log('--------------------------------------------------------------------------------');

// Check environment variables
console.log('Environment variables:');
console.log('NODE_ENV:', process.env.NODE_ENV || 'Not set (defaulting to development)');
console.log('AWS_REGION:', process.env.AWS_REGION || 'Not set');
console.log('AWS_S3_BUCKET_NAME:', process.env.AWS_S3_BUCKET_NAME || 'Not set');
console.log('AWS credentials configured:', !!process.env.AWS_ACCESS_KEY_ID && !!process.env.AWS_SECRET_ACCESS_KEY);
console.log('SESSION_SECRET configured:', !!process.env.SESSION_SECRET);
console.log('--------------------------------------------------------------------------------');

// Check AWS S3 connectivity
async function checkS3() {
    console.log('Checking AWS S3 connectivity...');

    try {
        const s3Client = new S3Client({
            region: process.env.AWS_REGION || 'ap-southeast-2',
            credentials: {
                accessKeyId: process.env.AWS_ACCESS_KEY_ID,
                secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
            }
        });

        console.log('S3 client created');

        // List buckets as a simple check
        const response = await s3Client.send(new ListBucketsCommand({}));
        console.log('S3 connection successful');
        console.log('Available buckets:', response.Buckets.map(b => b.Name).join(', '));

        // Check if configured bucket exists
        const configuredBucket = process.env.AWS_S3_BUCKET_NAME;
        if (configuredBucket) {
            const bucketExists = response.Buckets.some(b => b.Name === configuredBucket);
            if (bucketExists) {
                console.log(`Configured bucket '${configuredBucket}' exists and is accessible`);
            } else {
                console.error(`WARNING: Configured bucket '${configuredBucket}' does not exist or is not accessible`);
            }
        }

        return true;
    } catch (error) {
        console.error('S3 connectivity check failed:', error.message);
        if (error.Code) console.error('AWS Error Code:', error.Code);
        if (error.$metadata) console.error('Error metadata:', JSON.stringify(error.$metadata));
        return false;
    }
}

// Check Firebase connectivity
async function checkFirebase() {
    console.log('--------------------------------------------------------------------------------');
    console.log('Checking Firebase connectivity...');

    try {
        // Firebase configuration
        const firebaseConfig = {
            apiKey: process.env.FIREBASE_API_KEY || "AIzaSyD1lJAV3m3b0wAKPww8moPHl6dD8-Mgv4M",
            authDomain: process.env.FIREBASE_AUTH_DOMAIN || "spythere-8b6c7.firebaseapp.com",
            databaseURL: process.env.FIREBASE_DATABASE_URL || "https://spythere-8b6c7-default-rtdb.asia-southeast1.firebasedatabase.app",
            projectId: process.env.FIREBASE_PROJECT_ID || "spythere-8b6c7",
            storageBucket: process.env.FIREBASE_STORAGE_BUCKET || "spythere-8b6c7.firebasestorage.app",
            messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || "953650363803",
            appId: process.env.FIREBASE_APP_ID || "1:953650363803:web:ceaad94aeecb2e274a753e"
        };

        // Initialize Firebase
        const app = initializeApp(firebaseConfig);
        const db = getDatabase(app);

        console.log('Firebase app initialized');

        // Try to read from the database
        const snapshot = await get(ref(db, 'health-check'));
        console.log('Firebase connectivity successful');

        return true;
    } catch (error) {
        console.error('Firebase connectivity check failed:', error.message);
        return false;
    }
}

// Run the checks
async function runHealthCheck() {
    let s3Success = false;
    let firebaseSuccess = false;

    try {
        s3Success = await checkS3();
        firebaseSuccess = await checkFirebase();

        console.log('--------------------------------------------------------------------------------');
        console.log('Health check summary:');
        console.log('AWS S3 connectivity:', s3Success ? 'SUCCESS' : 'FAILED');
        console.log('Firebase connectivity:', firebaseSuccess ? 'SUCCESS' : 'FAILED');

        if (!s3Success || !firebaseSuccess) {
            console.log('\nSuggested fixes:');

            if (!s3Success) {
                console.log('- Check that your AWS credentials are correct in .env file');
                console.log('- Make sure the S3 bucket exists in the correct region');
                console.log('- Verify that the IAM user has permission to access the bucket');
            }

            if (!firebaseSuccess) {
                console.log('- Check that your Firebase configuration is correct');
                console.log('- Verify that the Firebase database exists and is accessible');
            }
        }
    } catch (error) {
        console.error('Unexpected error during health check:', error);
    }
}

runHealthCheck(); 