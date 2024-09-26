const express = require('express');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const forge = require('node-forge');

const app = express();

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// JWT Secret Setup
function setupJWTSecret() {
  const jwtKeyPath = 'jwt.key';
  if (!fs.existsSync(jwtKeyPath)) {
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(jwtKeyPath, jwtSecret, 'utf8');
    console.log('New JWT secret generated and saved to jwt.key');
    return jwtSecret;
  }
  console.log('Reading JWT secret from jwt.key file...');
  return fs.readFileSync(jwtKeyPath, 'utf8');
}

const JWT_SECRET = setupJWTSecret();

// File Upload Setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname))
  }
});

const upload = multer({ storage: storage });

// SSL Certificate Generation
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

const sslCert = generateSelfSignedCertificate();
fs.writeFileSync('server.crt', sslCert.cert);
fs.writeFileSync('server.key', sslCert.privateKey);

const httpsOptions = {
  key: sslCert.privateKey,
  cert: sslCert.cert
};

// Helper Functions
function generateToken(ip) {
  return jwt.sign({ ip }, JWT_SECRET);
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

function getPublicIP() {
  return new Promise((resolve, reject) => {
    https.get('https://api.ipify.org', (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', (err) => reject(err));
  });
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/upload', upload.single('file-upload'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file was uploaded.' });
  }
  res.json({ 
    message: 'File uploaded successfully', 
    filename: req.file.filename,
    originalName: req.file.originalname
  });
});

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

// Authentication Middleware
const customUrlParam = Math.floor(Math.random() * 1000000);

const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function promptForAccess(ip) {
  return new Promise((resolve) => {
    rl.question(`Allow user with IP ${ip}? (y/n): `, (answer) => {
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

app.use(async (req, res, next) => {
  const uploads = req.path === '/uploads/uploads.html'; 
  const providedKey = req.query.key;
  const clientIP = req.ip;

  if (providedKey === customUrlParam.toString() || (uploads && providedKey === customUrlParam.toString())) {
    next();
  } else {
    console.log(`User visited from IP: ${clientIP}`);
    const allow = await promptForAccess(clientIP);
    if (allow) {
      next();
    } else {
      return res.status(403).send('Access Denied');
    }
  }
});

// Start Server
getPublicIP().then((ip) => {
  const port = 443;
  const server = https.createServer(httpsOptions, app);
  server.listen(port, () => {
    console.log(`HTTPS Server running at https://${ip}:${port}/?key=${customUrlParam}`);
    console.log(`Access this URL on your phone's browser`);
  });
}).catch((err) => {
  console.error('Error getting public IP:', err);
});
