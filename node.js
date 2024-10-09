const secureServer = require('./secureserver');
const path = require('path');
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const readline = require('readline');
const sharp = require('sharp');



// Get the app instance from secureServer
const app = secureServer.app;


const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});





app.get('/uploads', secureServer.checkSessionAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'uploads', 'uploads.html'));
});


app.get('/uploads/:filename', secureServer.checkSessionAuth, (req, res) => {
  const filename = req.params.filename;
  res.sendFile(path.join(__dirname, 'uploads', filename));
});





// Modify your API endpoint to include thumbnail information
app.get('/api/files', secureServer.checkSessionAuth, (req, res) => {
  fs.readdir(path.join(__dirname, 'uploads'), (err, files) => {
    if (err) {
      res.status(500).json({ error: 'Unable to read directory' });
    } else {
      const fileInfo = files
        .filter(file => file !== 'uploads.html' && !file.startsWith('thumb_'))
        .map(file => ({
          name: file,
          thumbnail: `thumb_${file}`
        }));
      res.json(fileInfo);
    }
  });
});









/*
app.use('/uploads', (req, res, next) => {
  // Always allow static files without authentication
  if (req.path.match(/\.(css|jpg|jpeg|png|gif|mov|pdf|js)$/)) {
    return next();
  }

  // Check if the user has secret and encrypt cookies
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;

  if (clientSecretHash && clientEncryptHash) {
    // User has been previously verified, apply checkSessionAuth
    secureServer.checkSessionAuth(req, res, next);
  } else {
    // User hasn't been verified yet, allow access without authentication
    next();
  }
});
*/




/*
app.use('/uploads', (req, res, next) => {
  if (req.path.match(/\.(jpeg|jpg|gif|png)$/i)) {
    res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
  }
  next();
});
*/

// Configure multer for multiple file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});
const upload = multer({ storage: storage });








// Modify your upload handling route
app.post('/upload', upload.array('file-upload'), async (req, res) => {
  if (req.files && req.files.length > 0) {
    const fileNames = [];
    for (const file of req.files) {
      fileNames.push(file.filename);
      
      // Generate thumbnail for image files
      if (file.mimetype.startsWith('image/')) {
        const thumbnailName = `thumb_${file.filename}`;
        await sharp(file.path)
          .withMetadata()
          .rotate()
          .resize(200, 200, { fit: 'cover' })
          .toFile(path.join('uploads', thumbnailName));
      }
    }
    res.json({ message: 'Files uploaded successfully', fileNames: fileNames });
  } else {
    res.status(400).json({ message: 'No files uploaded' });
  }
});


secureServer.start();
