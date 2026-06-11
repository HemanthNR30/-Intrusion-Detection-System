const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const axios = require('axios');
const CryptoJS = require('crypto-js');
require('dotenv').config();

const SECRET_KEY = process.env.SECRET_KEY || "nids-secret-key-2024";

function hashAlert(alert) {
  const alertString = JSON.stringify({
    id: alert.id,
    timestamp: alert.timestamp,
    prediction: alert.prediction,
    confidence: alert.confidence,
    severity: alert.severity
  });
  return CryptoJS.SHA256(alertString).toString();
}

function encryptAlert(alert) {
  const alertString = JSON.stringify(alert);
  return CryptoJS.AES.encrypt(alertString, SECRET_KEY).toString();
}

function decryptAlert(encryptedData) {
  const bytes = CryptoJS.AES.decrypt(encryptedData, SECRET_KEY);
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(cors());
app.use(express.json());

let alerts = [];
let stats = {
  total_flows: 0,
  total_attacks: 0,
  attack_types: {},
  last_updated: new Date()
};

app.get('/', (req, res) => {
  res.json({ status: 'NIDS Backend running', port: process.env.PORT });
});

app.get('/alerts', (req, res) => {
  res.json(alerts.slice(-100));
});

app.get('/stats', (req, res) => {
  res.json(stats);
});

app.delete('/alerts', (req, res) => {
  alerts = [];
  res.json({ message: 'Alerts cleared' });
});

app.get('/alerts/encrypted', (req, res) => {
  const encryptedAlerts = alerts.slice(-100).map(a => ({
    id: a.id,
    hash: a.hash,
    encrypted: a.encrypted,
    timestamp: a.timestamp
  }));
  res.json(encryptedAlerts);
});

app.post('/alerts/verify', (req, res) => {
  const { id } = req.body;
  const alert = alerts.find(a => a.id === id);

  if (!alert) {
    return res.json({ verified: false, reason: "Alert not found" });
  }

  const recomputedHash = hashAlert({
    id: alert.id,
    timestamp: alert.timestamp,
    prediction: alert.prediction,
    confidence: alert.confidence,
    severity: alert.severity
  });

  const isValid = recomputedHash === alert.hash;

  res.json({
    verified: isValid,
    original_hash: alert.hash,
    computed_hash: recomputedHash,
    message: isValid
      ? "Alert integrity verified — not tampered"
      : "ALERT TAMPERED — hashes do not match"
  });
});

app.post('/alerts/decrypt', (req, res) => {
  const { id, key } = req.body;

  if (!key || key !== SECRET_KEY) {
    return res.json({
      success: false,
      reason: "Invalid secret key — access denied"
    });
  }

  const alert = alerts.find(a => a.id === id);
  if (!alert) {
    return res.json({ success: false, reason: "Alert not found" });
  }

  try {
    const decrypted = decryptAlert(alert.encrypted);
    res.json({
      success: true,
      decrypted: decrypted,
      message: "AES decryption successful"
    });
  } catch (err) {
    res.json({ success: false, reason: "Decryption failed" });
  }
});

app.post('/ai/analyze', async (req, res) => {
  const { attack_type, confidence, severity, question } = req.body;

  const remediation = {
    "Bot": {
      what: "Bot attacks use compromised machines to perform automated malicious activities like credential stuffing, scraping, or DDoS participation.",
      immediate: "Block the source IP immediately using your firewall. Rate-limit requests from suspicious IPs and enable CAPTCHA on login endpoints.",
      prevention: "Deploy a Web Application Firewall (WAF), use bot detection services like Cloudflare, and monitor for unusual traffic patterns regularly."
    },
    "DoS Hulk": {
      what: "DoS Hulk generates a massive volume of unique HTTP requests to overwhelm and crash web servers.",
      immediate: "Enable rate limiting on your web server immediately. Block the attacking IP and restart affected services if they are unresponsive.",
      prevention: "Use a CDN with DDoS protection (Cloudflare/AWS Shield), configure connection limits in nginx/Apache, and set up auto-scaling."
    },
    "DoS GoldenEye": {
      what: "GoldenEye is a HTTP DoS tool that keeps connections open to exhaust server resources and cause denial of service.",
      immediate: "Restart the web server and block the source IP. Reduce the maximum connection timeout in your server configuration.",
      prevention: "Configure connection rate limiting, enable SYN cookies, and use a reverse proxy like nginx to absorb connection floods."
    },
    "DoS Slowhttptest": {
      what: "Slowhttptest sends partial HTTP requests slowly to keep connections open and exhaust server connection pools.",
      immediate: "Set minimum request timeout values in your server config. Block slow connection IPs using fail2ban or equivalent.",
      prevention: "Configure minimum request rate thresholds, limit concurrent connections per IP, and use a WAF to detect slow HTTP attacks."
    },
    "DoS slowloris": {
      what: "Slowloris holds multiple connections open by sending partial HTTP headers, exhausting the server's connection limit.",
      immediate: "Install and configure mod_reqtimeout on Apache or equivalent. Limit the number of connections per IP address immediately.",
      prevention: "Use nginx instead of Apache (more resistant to slowloris), enable connection timeouts, and deploy Cloudflare or similar CDN protection."
    },
    "Heartbleed": {
      what: "Heartbleed exploits a critical vulnerability in OpenSSL that allows attackers to read sensitive memory including private keys and passwords.",
      immediate: "Immediately update OpenSSL to a patched version. Revoke and reissue all SSL certificates. Force password resets for all users.",
      prevention: "Keep OpenSSL and all dependencies updated. Use automated vulnerability scanning tools and subscribe to security advisories."
    },
    "PortScan": {
      what: "Port scanning probes your network to discover open ports and running services, usually as reconnaissance before an attack.",
      immediate: "Block the scanning IP in your firewall. Review which ports are unnecessarily open and close them immediately.",
      prevention: "Implement port knocking, use a firewall to whitelist only required ports, and deploy an IDS to alert on future scan attempts."
    },
    "Web Attack": {
      what: "Web attacks include SQL injection, XSS, and command injection attempts targeting vulnerabilities in web applications.",
      immediate: "Check application logs for successful injection attempts. Patch the vulnerable endpoint immediately and sanitize all inputs.",
      prevention: "Use parameterized queries, implement a WAF, conduct regular penetration testing, and follow OWASP Top 10 guidelines."
    }
  };

  const info = remediation[attack_type] || {
    what: `${attack_type} is a network-based attack targeting system availability or data integrity.`,
    immediate: "Isolate the affected system, block the source IP, and review system logs for any successful intrusions.",
    prevention: "Keep all systems patched, use network segmentation, deploy an IDS/IPS, and conduct regular security audits."
  };

  let response;

  if (question) {
    const q = question.toLowerCase();
    if (q.includes('block') || q.includes('stop') || q.includes('prevent')) {
      response = `To block a ${attack_type} attack: ${info.immediate} For long-term prevention: ${info.prevention}`;
    } else if (q.includes('what') || q.includes('how does') || q.includes('explain')) {
      response = `${info.what} This attack type is classified as ${severity} severity with ${confidence}% detection confidence.`;
    } else if (q.includes('damage') || q.includes('impact') || q.includes('risk')) {
      response = `A ${attack_type} attack can cause significant disruption. ${info.what} At ${confidence}% confidence and ${severity} severity, immediate action is recommended: ${info.immediate}`;
    } else if (q.includes('firewall') || q.includes('rule')) {
      response = `Recommended firewall rules for ${attack_type}: Block the source IP immediately, enable rate limiting (max 100 requests/min per IP), and set connection timeouts to 30 seconds. ${info.prevention}`;
    } else {
      response = `Regarding your question about ${attack_type}: ${info.what} ${info.immediate}`;
    }
  } else {
    response = `What this attack does: ${info.what}\n\nImmediate action: ${info.immediate}\n\nLong-term prevention: ${info.prevention}`;
  }

  res.json({ success: true, response });
});

const fs = require('fs');
const path = require('path');
const readline = require('readline');

let csvRows = [];
let currentIndex = 0;

async function loadCSV() {
  const csvPath = path.join(__dirname, '../data/cleaned_dataset.csv');

  if (!fs.existsSync(csvPath)) {
    console.log('CSV not found — using random simulation mode');
    return false;
  }

  return new Promise((resolve) => {
    const rows = [];
    const rl = readline.createInterface({
      input: fs.createReadStream(csvPath),
      crlfDelay: Infinity
    });

    let headers = null;
    let count = 0;

    rl.on('line', (line) => {
      if (count > 5000) return;
      if (!headers) {
        headers = line.split(',');
      } else {
        const values = line.split(',');
        const row = {};
        headers.forEach((h, i) => { row[h] = values[i]; });
        rows.push(row);
        count++;
      }
    });

    rl.on('close', () => {
      csvRows = rows;
      console.log(`Loaded ${csvRows.length} rows from dataset`);
      resolve(true);
    });
  });
}

async function startSimulator() {
  const loaded = await loadCSV();

  setInterval(async () => {
    try {
      let features, actualLabel;

      if (loaded && csvRows.length > 0) {
        const row = csvRows[currentIndex % csvRows.length];
        currentIndex++;
        actualLabel = row['Label'] || 'UNKNOWN';

        features = Object.entries(row)
          .filter(([k]) => k !== 'Label' && k !== 'label_encoded')
          .map(([, v]) => {
            const num = parseFloat(v);
            return isNaN(num) ? 0 : num;
          });
      } else {
        features = Array.from({ length: 78 }, () => Math.random() * 100);
        actualLabel = 'SIMULATED';
      }

      const response = await axios.post(
        `${process.env.FASTAPI_URL}/predict`,
        { features },
        { timeout: 3000 }
      );

      const prediction = response.data;
      stats.total_flows++;
      stats.last_updated = new Date();

      if (prediction.is_attack) {
        stats.total_attacks++;
        stats.attack_types[prediction.prediction] =
          (stats.attack_types[prediction.prediction] || 0) + 1;

        const alertData = {
          id: Date.now(),
          timestamp: new Date().toISOString(),
          prediction: prediction.prediction,
          confidence: prediction.confidence,
          severity: prediction.severity,
          actual: actualLabel,
          is_attack: true
        };

        const hash = hashAlert(alertData);
        const encrypted = encryptAlert(alertData);

        const alert = {
          ...alertData,
          hash: hash,
          encrypted: encrypted,
          verified: true
        };

        alerts.push(alert);
        if (alerts.length > 500) alerts.shift();

        io.emit('new-alert', alert);
        io.emit('stats-update', stats);

        console.log(`ATTACK: ${prediction.prediction} | SHA256: ${hash.slice(0, 16)}...`);
      } else {
        io.emit('stats-update', stats);
      }

    } catch (err) {
      console.error('Simulator error:', err.message);
    }
  }, 800);

  console.log('Traffic simulator started!');
}

io.on('connection', (socket) => {
  console.log('Dashboard connected:', socket.id);
  socket.emit('initial-alerts', alerts.slice(-50));
  socket.emit('stats-update', stats);
  socket.on('disconnect', () => {
    console.log('Dashboard disconnected:', socket.id);
  });
});

server.listen(process.env.PORT, async () => {
  console.log(`Backend running on http://localhost:${process.env.PORT}`);
  await startSimulator();
});