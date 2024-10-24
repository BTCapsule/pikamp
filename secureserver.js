const express = require('express');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const forge = require('node-forge');
const cookieParser = require('cookie-parser');
const readline = require('readline');


const WebSocket = require('ws');
const app = express();
app.use(express.json());

app.use(cookieParser());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));




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
  for (const file of files) {
    try {
      const encryptedContent = fs.readFileSync(file, 'utf8');
      const decryptedContent = decryptData(encryptedContent, encryptHash);
      if (decryptedContent.split('\n')[0] === secretHash) {
        return true;
      }
    } catch (error) {
      // Silently continue to the next file
    }
  }
  return false;
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
     // Silently continue to the next file
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
        return pin ? 'pin' : '/';
      }
    } catch (error) {
      // Silently continue to the next file
    }
  }
  return false;
}



async function checkSessionAuth(req, res, next) {
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;

  const files = getSecretFiles();

  // If there are no secret files, allow access to main.html
  if (files.length === 0) {
    return next();
  }

  if (clientSecretHash && clientEncryptHash) {
    let fileFound = false;

    for (const file of files) {
      try {
        const encryptedContent = fs.readFileSync(file, 'utf8');
        const decryptedContent = decryptData(encryptedContent, clientEncryptHash);
        const [storedHash, pin] = decryptedContent.split('\n');
        
        if (storedHash === clientSecretHash) {
          fileFound = true;
          if (pin && !req.cookies.pin_verified) {
            return res.redirect('/pin');
          } else {
            // User is authenticated, set session cookie
            res.cookie('session_auth', 'true', { secure: true, sameSite: 'lax', maxAge: 3600000 });
            return next();
          }
        }
      } catch (error) {
        // If we can't decrypt the file with the client's encrypt hash,
        // it means this file doesn't belong to this client.
        // Continue to the next file.
      }
    }

    if (!fileFound) {
      // If we've reached this point, it means the client's cookies don't match any secret file
      // Clear all cookies
      for (const cookieName in req.cookies) {
        res.clearCookie(cookieName);
      }

      // Redirect to access denied page
      return res.redirect('/access-denied');
    }
  }

  // If no valid cookies are present, redirect to the main page
  res.redirect('/main');
}



let wss;

let clients = new Set();


 function setupWebSocket(server) {
  wss = new WebSocket.Server({ server });

  wss.on('connection', (ws) => {
    clients.add(ws);
    
    ws.on('close', () => {
      clients.delete(ws);
    });

    ws.on('message', (message) => {
      const data = JSON.parse(message);
      if (data.type === 'deviceResponse') {
        handleDeviceResponse(data);
      }
    });
  });
 }




function broadcastNewDevicePrompt(ip) {
  const message = JSON.stringify({ type: 'newDevicePrompt', ip });
  clients.forEach(client => client.send(message));
}





  let pendingPrompts = new Map();

function handleDeviceResponse(data) {
  const { ip, allow } = data;
  const resolver = pendingPrompts.get(ip);
  if (resolver) {
    resolver(allow);
    pendingPrompts.delete(ip);
    
    // Broadcast the response to all clients
    const responseMessage = JSON.stringify({ type: 'deviceResponseUpdate', ip, allow });
    clients.forEach(client => client.send(responseMessage));
    
    console.log(`New user with IP ${ip} was ${allow ? 'accepted' : 'denied'} by the client`);
  }
}



function promptForAccess(ip) {
  return new Promise((resolve) => {
    const existingFiles = getSecretFiles();
    const isFirstUser = existingFiles.length === 0;

    if (!isFirstUser) {
      broadcastNewDevicePrompt(ip);
    }
    
    let isResolved = false;

    const resolveOnce = (allow) => {
      if (!isResolved) {
        isResolved = true;
        pendingPrompts.delete(ip);
        
        // Broadcast the response to all clients
        const responseMessage = JSON.stringify({ type: 'deviceResponseUpdate', ip, allow });
        clients.forEach(client => client.send(responseMessage));
        
        console.log(`New user with IP ${ip} was ${allow ? 'accepted' : 'denied'} by the ${isFirstUser ? 'server' : 'server or client'}`);
        resolve(allow);
      }
    };

    if (!isFirstUser) {
      pendingPrompts.set(ip, (clientAllow) => {
        if (clientAllow) {
          resolveOnce(true);
        }
      });
    }

    rl.question(`Allow user with IP ${ip}? (y/n): `, (answer) => {
      const serverAllow = answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';
      resolveOnce(serverAllow);
    });
  });
}

app.post('/remove-device', checkSessionAuth, (req, res) => {
  const files = getSecretFiles();
  const newFiles = [];

  files.forEach(file => {
    const match = file.match(/user(\d+)\.secret/);
    if (match) {
      const userNumber = parseInt(match[1]);
      newFiles.push({ fileName: file, userNumber });
    }
  });

  if (newFiles.length === 0) {
    return res.status(404).json({ success: false, message: 'No new users to remove' });
  }

  // Sort files by user number to get the latest one
  newFiles.sort((a, b) => b.userNumber - a.userNumber);
  const latestFile = newFiles[0];

  fs.unlink(latestFile.fileName, (err) => {
    if (err) {
      console.error(`Error removing file: ${err}`);
      res.status(500).json({ success: false, message: 'Failed to remove user' });
    } else {
      // Check if the removed file matches the current user's cookies
      const clientSecretHash = req.cookies.secret;
      const clientEncryptHash = req.cookies.encrypt;
      
      let shouldLogout = false;

      try {
        const encryptedContent = fs.readFileSync(latestFile.fileName, 'utf8');
        const decryptedContent = decryptData(encryptedContent, clientEncryptHash);
        const [storedHash, _] = decryptedContent.split('\n');
        
        if (storedHash === clientSecretHash) {
          shouldLogout = true;
        }
      } catch (error) {
        // If there's an error reading the file, it's likely already deleted
        // so we don't need to do anything here
      }

      res.json({ 
        success: true, 
        message: 'User removed successfully', 
        removedUser: latestFile.userNumber,
        remainingUsers: newFiles.length - 1,
        action: shouldLogout ? 'logout' : 'none'
      });
    }
  });
});


app.get('/cookies.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'cookies.js'));
});


app.get('/access-denied', (req, res) => {
  res.status(403).sendFile(path.join(__dirname, 'access-denied.html'));
});




app.get('/createpin', (req, res) => {
  res.sendFile(path.join(__dirname, 'createpin.html'));
});

app.get('/pin', (req, res) => {
  res.sendFile(path.join(__dirname, 'pin.html'));
});

app.post('/create-pin', express.json(), (req, res) => {
  const { pin } = req.body;
  const newSecretHash = generateHash();
  const newEncryptHash = generateHash();
  
  createNewSecretFile(newSecretHash, newEncryptHash, pin);

  res.cookie('secret', newSecretHash, { secure: true, sameSite: 'lax', maxAge: 36000000000 });
  res.cookie('encrypt', newEncryptHash, { secure: true, sameSite: 'lax', maxAge: 36000000000 });


  res.sendStatus(200);
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
        // PIN is correct, set a cookie to indicate PIN verification
 res.cookie('pin_verified', 'true', { secure: true, sameSite: 'lax', maxAge: 3600000 });
    res.cookie('session_auth', 'true', { secure: true, sameSite: 'lax', maxAge: 3600000 });
    
    // Get the stored redirect URL
    const redirectUrl = '/';
   
    // Clear the redirect cookie
    res.clearCookie('redirect_after_pin');
    
    return res.json({ success: true, redirectUrl });
      }
    } catch (error) {
     // Silently continue to the next file
    }
  }

  res.status(401).json({ message: 'Invalid PIN' });
});







app.get('/', checkSessionAuth, (req, res) => {
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;
  const pinVerified = req.cookies.pin_verified;

  if (clientSecretHash && clientEncryptHash) {
    const files = getSecretFiles();
    for (const file of files) {
      try {
        const encryptedContent = fs.readFileSync(file, 'utf8');
        const decryptedContent = decryptData(encryptedContent, clientEncryptHash);
        const [storedHash, storedPin] = decryptedContent.split('\n');
        if (storedHash === clientSecretHash) {
          if (storedPin && !pinVerified) {
            return res.redirect('/pin');
          } else {
            // User is fully authenticated, set a session cookie
            res.cookie('session_auth', 'true', { secure: true, sameSite: 'lax', maxAge: 3600000 });
            return res.sendFile(path.join(__dirname, 'index.html'));
          }
        }
      } catch (error) {
       // Silently continue to the next file
      }
    }
  }

  res.redirect('/main');
});





app.use(async (req, res, next) => {
  const clientIP = req.ip;
  const clientSecretHash = req.cookies.secret;
  const clientEncryptHash = req.cookies.encrypt;
  const pinVerified = req.cookies.pin_verified;

  if (clientSecretHash && clientEncryptHash) {
    const authResult = await checkHashAndPin(clientSecretHash, clientEncryptHash);
    if (authResult === '/' || (authResult === 'pin' && pinVerified)) {
      return next();
    } else if (authResult === 'pin' && !pinVerified) {
      return res.sendFile(path.join(__dirname, 'pin.html'));
    }
  }

  if (req.path !== '/main') {
    return res.redirect('/main');
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
app.get('/main', (req, res) => {
  res.sendFile(path.join(__dirname, 'main.html'));
});















function start() {
  app.use(cookieParser());
  app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));

  const sslCert = generateSelfSignedCertificate();
  fs.writeFileSync('server.crt', sslCert.cert);
  fs.writeFileSync('server.key', sslCert.privateKey);

  const httpsOptions = {
    key: sslCert.privateKey,
    cert: sslCert.cert
  };

  getPublicIP()
    .then((ip) => {
      const port = 443;
      const server = https.createServer(httpsOptions, app);
      
	  setupWebSocket(server);
	  
      server.listen(port, () => {
        console.log(`HTTPS Server running at https://${ip}:${port}/`);
        console.log(`Access this URL on your phone's browser`);
      });
    })
    .catch((err) => {
      console.error('Error getting public IP:', err);
    });
}


module.exports = {
  start,
  app,
  checkHashAndPin,
  generateHash,
  encryptData,
  decryptData,
  getSecretFiles,
  updateSecretFile,
  checkSessionAuth
};



