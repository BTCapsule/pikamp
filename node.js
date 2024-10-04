const express = require('express');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const forge = require('node-forge');
const cookieParser = require('cookie-parser');
const readline = require('readline');

const app = express();

// Middleware
app.use(cookieParser());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// File Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
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

  const attrs = [
    { name: 'commonName', value: 'localhost' },
    { name: 'countryName', value: 'US' },
    { shortName: 'ST', value: 'Virginia' },
    { name: 'localityName', value: 'Blacksburg' },
    { name: 'organizationName', value: 'Test' },
    { shortName: 'OU', value: 'Test' }
  ];

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

// Utility Functions
function getPublicIP() {
  return new Promise((resolve, reject) => {
    https.get('https://api.ipify.org', (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', (err) => reject(err));
  });
}

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

function generateHash() {
  return crypto.createHash('sha256').update(crypto.randomBytes(64)).digest('hex');
}

function encryptData(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

function decryptData(data, key) {
  const [ivHex, encryptedHex] = data.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function getSecretFiles() {
  return fs.readdirSync(__dirname).filter(file => file.endsWith('.secret'));
}

function createNewSecretFile(secretHash, encryptHash, pin = '') {
  const files = getSecretFiles();
  const newUserNumber = files.length > 0 ? Math.max(...files.map(f => parseInt(f.match(/\d+/)[0]))) + 1 : 1;
  const fileName = `user${newUserNumber}.secret`;
  const content = `${secretHash}\n${pin}`;
  const encryptedContent = encryptData(content, encryptHash);
  fs.writeFileSync(fileName, encryptedContent);
}



function checkHash(secretHash, encryptHash) {
  const files = getSecretFiles();
  return files.some(file => {
    try {
      const encryptedContent = fs.readFileSync(file, 'utf8');
      const decryptedContent = decryptData(encryptedContent, encryptHash);
      return decryptedContent === secretHash;
    } catch (error) {
      console.error('Error checking hash:', error);
      return false;
    }
  });
}




function updateSecretFile(oldSecretHash, oldEncryptHash, newSecretHash, newEncryptHash) {
  const files = getSecretFiles();
  for (const file of files) {
    try {
      const encryptedContent = fs.readFileSync(file, 'utf8');
      const decryptedContent = decryptData(encryptedContent, oldEncryptHash);
      if (decryptedContent === oldSecretHash) {
        // This is the file we need to update
        const newEncryptedContent = encryptData(newSecretHash, newEncryptHash);
        fs.writeFileSync(file, newEncryptedContent);
        console.log(`Updated file: ${file}`);
        return true;
      }
    } catch (error) {
      console.error(`Error processing file ${file}:`, error);
    }
  }
  console.error('No matching secret file found to update');
  return false;
}


async function checkHashAndPin(secretHash, encryptHash) {
  const files = getSecretFiles();
  for (const file of files) {
    try {
      const encryptedContent = fs.readFileSync(file, 'utf8');
      const decryptedContent = decryptData(encryptedContent, encryptHash);
      const [storedHash, pin] = decryptedContent.split('\n');
      if (storedHash === secretHash) {
        return pin ? 'pin' : 'main';
      }
    } catch (error) {
      console.error('Error checking hash and pin:', error);
    }
  }
  return false;
}





app.get('/auth-success', (req, res) => {
  res.redirect('/main');
});


app.post('/create-pin', express.json(), (req, res) => {
  const { pin } = req.body;
  const newSecretHash = generateHash();
  const newEncryptHash = generateHash();
  
  createNewSecretFile(newSecretHash, newEncryptHash, pin);

  res.cookie('secret', newSecretHash, { secure: true, sameSite: 'lax', maxAge: 3600000 });
  res.cookie('encrypt', newEncryptHash, { secure: true, sameSite: 'lax', maxAge: 3600000 });

  res.sendFile(path.join(__dirname, 'main.html'));
});






app.post('/verify-pin', express.json(), (req, res) => {
  const { pin } = req.body;
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;

  const files = getSecretFiles();
  for (const file of files) {
    try {
      const encryptedContent = fs.readFileSync(file, 'utf8');
      const decryptedContent = decryptData(encryptedContent, clientEncryptHash);
      const [storedHash, storedPin] = decryptedContent.split('\n');
      if (storedHash === clientSecretHash && storedPin === pin) {
        // Generate new hashes
        const newSecretHash = generateHash();
        const newEncryptHash = generateHash();

        // Update the existing secret file
        const newContent = `${newSecretHash}\n${storedPin}`;
        const newEncryptedContent = encryptData(newContent, newEncryptHash);
        fs.writeFileSync(file, newEncryptedContent);

        // Set new cookies
        res.cookie('secret', newSecretHash, { secure: true, sameSite: 'lax', maxAge: 3600000 });
        res.cookie('encrypt', newEncryptHash, { secure: true, sameSite: 'lax', maxAge: 3600000 });

        return res.sendStatus(200);
      }
    } catch (error) {
      console.error('Error verifying PIN:', error);
    }
  }

  res.status(401).json({ message: 'Invalid PIN' });
});









// Middleware for access control



app.use(async (req, res, next) => {
  const clientIP = req.ip;
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;

  if (clientSecretHash && clientEncryptHash) {
    const authResult = await checkHashAndPin(clientSecretHash, clientEncryptHash);
    if (authResult === 'main') {
      return next();
    } else if (authResult === 'pin') {
      return res.sendFile(path.join(__dirname, 'pin.html'));
    }
  }

  if (req.path !== '/') {
    return res.redirect('/');
  }

  console.log(`User visited from IP: ${clientIP}`);
  const allow = await promptForAccess(clientIP);

  if (allow) {
    return res.sendFile(path.join(__dirname, 'createpin.html'));
  } else {
    return res.status(403).send('Access Denied');
  }
});











// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});








app.get('/main', (req, res) => {
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;

  if (clientSecretHash && clientEncryptHash) {
    const files = getSecretFiles();
    for (const file of files) {
      try {
        const encryptedContent = fs.readFileSync(file, 'utf8');
        const decryptedContent = decryptData(encryptedContent, clientEncryptHash);
        const [storedHash, pin] = decryptedContent.split('\n');
        if (storedHash === clientSecretHash) {
          // Generate new hashes
          const newSecretHash = generateHash();
          const newEncryptHash = generateHash();

          // Update the existing secret file
          const newContent = `${newSecretHash}\n${pin}`;
          const newEncryptedContent = encryptData(newContent, newEncryptHash);
          fs.writeFileSync(file, newEncryptedContent);

          // Set new cookies
          res.cookie('secret', newSecretHash, { secure: true, sameSite: 'lax', maxAge: 3600000 });
          res.cookie('encrypt', newEncryptHash, { secure: true, sameSite: 'lax', maxAge: 3600000 });

          return res.sendFile(path.join(__dirname, 'main.html'));
        }
      } catch (error) {
        console.error('Error processing file:', error);
      }
    }
  }

  console.log('Redirecting to /');
  res.redirect('/');
});












// Start Server
getPublicIP()
  .then((ip) => {
    const port = 443;
    const server = https.createServer(httpsOptions, app);
    
    server.listen(port, () => {
      console.log(`HTTPS Server running at https://${ip}:${port}/`);
      console.log(`Access this URL on your phone's browser`);
    });
  })
  .catch((err) => {
    console.error('Error getting public IP:', err);
  });





