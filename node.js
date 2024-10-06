const secureServer = require('./secureserver');
const path = require('path');
const express = require('express');

// Get the app instance from secureServer
const app = secureServer.app;

// Add the route for uploads.html with security checks
app.get('/uploads', async (req, res) => {
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;

  if (clientSecretHash && clientEncryptHash) {
    const authResult = await secureServer.checkHashAndPin(clientSecretHash, clientEncryptHash);
    if (authResult === 'main') {
      // User is authenticated, serve the uploads.html file
      return res.sendFile(path.join(__dirname, 'uploads', 'uploads.html'));
    } else if (authResult === 'pin') {
      // Redirect to PIN entry if needed
      return res.sendFile(path.join(__dirname, 'pin.html'));
    }
  }

  // If not authenticated, redirect to the home page
  res.redirect('/');
});

// Add file upload handling
const multer = require('multer');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});
const upload = multer({ storage: storage });

app.post('/upload', upload.single('file-upload'), (req, res) => {
  if (req.file) {
    res.json({ message: 'File uploaded successfully', filename: req.file.filename });
  } else {
    res.status(400).json({ message: 'No file uploaded' });
  }
});



secureServer.start();




