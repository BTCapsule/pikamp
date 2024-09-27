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

const cookieParser = require('cookie-parser');
app.use(cookieParser());


// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


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

/*function generateToken(ip) {
  return jwt.sign({ ip }, JWT_SECRET, { expiresIn: '1h' });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}*/

function getPublicIP() {
  return new Promise((resolve, reject) => {
    https.get('https://api.ipify.org', (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', (err) => reject(err));
  });
}


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
      
    });
  }).catch((err) => {
    console.error('Error getting public IP:', err);
    res.status(500).json({ error: 'Failed to get public IP' });
  });
});



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




function setupSecret() {
  const secretKeyPath = 'secret.key';
  if (!fs.existsSync(secretKeyPath)) {
    const secret = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(secretKeyPath, secret, 'utf8');
    console.log('New secret generated and saved to secret.key');
    return secret;
  }
  console.log('Reading secret from secret.key file...');
  return fs.readFileSync(secretKeyPath, 'utf8').trim();
}






let accessGranted = false;

app.use(async (req, res, next) => {
  try {
    const clientIP = req.ip;
    const clientSecret = req.cookies.secret;

    if (accessGranted && clientSecret) {
      const storedSecret = fs.readFileSync('secret.key', 'utf8').trim();
      if (clientSecret === storedSecret) {
        return next();
      }
    }

    console.log(`User visited from IP: ${clientIP}`);
    const allow = await promptForAccess(clientIP);
    if (allow) {
      accessGranted = true;
      const secret = setupSecret();
      res.cookie('secret', secret, { httpOnly: true, secure: true, maxAge: 3600000 }); // 1 hour expiry
      res.redirect('/main');
    } else {
      res.status(403).send('Access Denied');
    }
  } catch (error) {
    console.error('Error in middleware:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/main', (req, res) => {
  const clientSecret = req.cookies.secret;
  const storedSecret = fs.readFileSync('secret.key', 'utf8').trim();
  
  if (clientSecret && clientSecret === storedSecret) {
    res.sendFile(path.join(__dirname, 'main.html'));
  } else {
    res.redirect('/');
  }
});



// Start Server
getPublicIP().then((ip) => {
  const port = 443;
  const server = https.createServer(httpsOptions, app);
  server.listen(port, () => {
    console.log(`HTTPS Server running at https://${ip}:${port}/`);
    console.log(`Access this URL on your phone's browser`);
  });
}).catch((err) => {
  console.error('Error getting public IP:', err);
});
