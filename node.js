const QRCode = require('qrcode');
const opn = require('opn');
const fs = require('fs');
let express = require('express');
let cors = require('cors');
let app = express();
const { createProxyMiddleware } = require('http-proxy-middleware');
const https = require('https');
const publicIp = require('ip');
const forge = require('node-forge');
const os = require('os');




const multer = require('multer');
const path = require('path');


// Set up storage for uploaded files
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/') // Make sure this folder exists
    },
    filename: function (req, file, cb) {
        // Preserve the original extension and use a timestamp to ensure uniqueness
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname))
    }
});

// Create the multer instance
const upload = multer({ storage: storage });

// Add this route to handle file uploads
app.post('/upload', upload.single('file-upload'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file was uploaded.' });
    }

    // Send back the filename so it can be used for downloading
    res.json({ 
        message: 'File uploaded successfully', 
        filename: req.file.filename,
        originalName: req.file.originalname
    });
});





app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));




function generateRandomNumber() {
  return Math.floor(Math.random() * 1000000); // Generates a random number between 0 and 999999
}



function generateSelfSignedCertificate() {
  const pki = forge.pki;
  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const attrs = [{
    name: 'commonName',
    value: 'localhost'
  }, {
    name: 'countryName',
    value: 'US'
  }, {
    shortName: 'ST',
    value: 'Virginia'
  }, {
    name: 'localityName',
    value: 'Blacksburg'
  }, {
    name: 'organizationName',
    value: 'Test'
  }, {
    shortName: 'OU',
    value: 'Test'
  }];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey);
  return {
    cert: pki.certificateToPem(cert),
    privateKey: pki.privateKeyToPem(keys.privateKey)
  };
}


function getPublicIP() {
  return new Promise((resolve, reject) => {
    https.get('https://api.ipify.org', (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        resolve(data);
      });
    }).on('error', (err) => {
      reject(err);
    });
  });
}


app.get('/getPublicIPAndParam', (req, res) => {
  getPublicIP().then((ip) => {
    res.json({
      publicIP: ip,
      customUrlParam: customUrlParam
    });
  }).catch((err) => {
    console.error('Error getting public IP:', err);
    res.status(500).json({ error: 'Failed to get public IP' });
  });
});







const sslCert = generateSelfSignedCertificate();

// Write the certificate and key to files
fs.writeFileSync('server.crt', sslCert.cert);
fs.writeFileSync('server.key', sslCert.privateKey);

const httpsOptions = {
  key: sslCert.privateKey,
  cert: sslCert.cert
};





const customUrlParam = generateRandomNumber();






app.use((req, res, next) => {
 const uploads = req.path === '/uploads/uploads.html'; 
 //const isTestchainPage = req.path === '/testchain/testchain.html';
  const providedKey = req.query.key;

  if (providedKey === customUrlParam.toString() || (uploads && providedKey === customUrlParam.toString())
 // (isTestchainPage && providedKey === customUrlParam.toString())
) {
    next();
  } else {
    return res.status(403).send('Access Denied');
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});



/*
app.get('/testchain.html', (req, res) => {
  const filePath = path.join(__dirname, 'testchain.html');
  console.log('Attempting to serve file:', filePath);
  res.sendFile(filePath);
});


// Proxy requests to /testchain to the testchain application
app.use('/testchain', createProxyMiddleware({ 
  target: 'http://localhost:3001', 
  changeOrigin: true,
  pathRewrite: {'^/testchain/api' : ''}
}));

// Your existing route handlers...

// Start the testchain application
const testchainApp = require('./testchain/testchain');
testchainApp.listen(3001, () => {
  console.log('Testchain app listening on port 3001');
});



*/




app.get('/uploads.html', (req, res) => {
  const filePath = path.join(__dirname, 'uploads.html');
  console.log('Attempting to serve file:', filePath);
  res.sendFile(filePath);
});


// Proxy requests to /testchain to the testchain application
app.use('/uploads', createProxyMiddleware({ 
  target: 'http://localhost:3002', 
  changeOrigin: true,
  pathRewrite: {'^/uploads/api' : ''}
}));

// Your existing route handlers...

// Start the testchain application
const uploadsApp = require('./uploads/uploads');
uploadsApp.listen(3002, () => {
  console.log('uploads app listening on port 3002');
});









// Start the main server
getPublicIP().then((ip) => {
  const port = 443; // or 3000 if not running as root
  const server = https.createServer(httpsOptions, app);
  server.listen(port, () => {
    console.log(`HTTPS Server running at https://${ip}:${port}/?key=${customUrlParam}`);
    console.log(`Access this URL on your phone's browser`);
  });
}).catch((err) => {
  console.error('Error getting public IP:', err);
});



// Add this line to serve static files from the Thunder folder
//app.use('/thunder', express.static(path.join(__dirname, 'thunder')));
