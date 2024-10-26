const secureServer = require('./secureserver');
const path = require('path');
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const readline = require('readline');



const exif = require('exif-parser');


// Get the app instance from secureServer
const app = secureServer.app;






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
      const fileInfo = files
        .filter(file => file !== 'uploads.html' && !file.startsWith('thumb_'))
        .map(file => ({
          name: file,
          thumbnail: `thumb_${file}`,
          mtime: fs.statSync(path.join(__dirname, 'uploads', file)).mtime.getTime()
        }))
        .sort((a, b) => b.mtime - a.mtime); // Sort by modification time, newest first
      res.json(fileInfo);
    }
  });
});







const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    // We'll keep the original filename for now
    cb(null, file.originalname)
  }
})

const upload = multer({ storage: storage })

app.post('/upload', secureServer.checkSessionAuth, upload.array('files'), (req, res) => {
  const uploadedFiles = req.files;
  const processedFiles = [];

  uploadedFiles.forEach(file => {
    const buffer = fs.readFileSync(file.path);
    let timestamp;

    try {
      const parser = exif.create(buffer);
      const result = parser.parse();
      
      // Try to get the original date from EXIF data
      if (result.tags.DateTimeOriginal) {
        // Parse the EXIF date string to a Date object
        const exifDate = new Date(result.tags.DateTimeOriginal * 1000);
        if (!isNaN(exifDate.getTime())) {
          timestamp = exifDate.getTime();
        } else {
          throw new Error('Invalid EXIF date');
        }
      } else {
        throw new Error('No EXIF date found');
      }
    } catch (error) {
      console.error('Error parsing EXIF data:', error);
      // If parsing fails or no valid EXIF date, use file creation time or current time
      timestamp = file.mtime ? new Date(file.mtime).getTime() : Date.now();
    }

    // Rename the file to include the timestamp
    const newFilename = `${timestamp}_${file.originalname}`;
    fs.renameSync(file.path, `uploads/${newFilename}`);

    processedFiles.push({
      originalName: file.originalname,
      newName: newFilename,
      timestamp: timestamp
    });
  });

  res.json({ message: 'Files uploaded successfully', files: processedFiles });
});



// Add this route to handle photo deletion
app.delete('/delete/:filename', secureServer.checkSessionAuth, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'uploads', filename);
    const thumbnailPath = path.join(__dirname, 'uploads', 'thumbnails', filename);

    fs.unlink(filePath, (err) => {
        if (err) {
            console.error('Error deleting file:', err);
            return res.json({ success: false, message: 'Failed to delete the file' });
        }

        // Also delete the thumbnail if it exists
        fs.unlink(thumbnailPath, (thumbErr) => {
            if (thumbErr && thumbErr.code !== 'ENOENT') {
                console.error('Error deleting thumbnail:', thumbErr);
            }

            res.json({ success: true, message: 'File deleted successfully' });
        });
    });
});





secureServer.start();
