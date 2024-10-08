const secureServer = require('./secureserver');
const path = require('path');
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const readline = require('readline');




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

app.get('/api/files', secureServer.checkSessionAuth, (req, res) => {
  fs.readdir(path.join(__dirname, 'uploads'), (err, files) => {
    if (err) {
      res.status(500).json({ error: 'Unable to read directory' });
    } else {
      res.json(files.filter(file => file !== 'uploads.html'));
    }
  });
});


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

// Handle multiple file uploads
app.post('/upload', upload.array('file-upload', 10), (req, res) => {
  if (req.files && req.files.length > 0) {
    const fileNames = req.files.map(file => file.filename);
    res.json({ message: 'Files uploaded successfully', fileNames: fileNames });
  } else {
    res.status(400).json({ message: 'No files uploaded' });
  }
});

secureServer.start();




