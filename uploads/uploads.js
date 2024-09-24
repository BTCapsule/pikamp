const https = require('https');
const crypto = require('crypto');
const publicIp = require('ip');
const forge = require('node-forge');
const opn = require('opn');
const fs = require('fs');
let express = require('express');
let cors = require('cors');
let app = express();
const path = require('path');
const os = require('os');



app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.get('/uplods/uploads.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'uploads.html'));
});
module.exports = app;
