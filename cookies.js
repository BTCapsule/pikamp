

// Common function to retrieve all cookies
function getCookies() {
    const cookies = {};
    document.cookie.split(';').forEach(cookie => {
        const [name, value] = cookie.trim().split('=');
        cookies[name] = value;
    });
    return cookies;
}

// Function for main.html
function checkSessionAuth() {
    const cookies = getCookies();
    const sessionAuth = cookies['session_auth'];
    if (sessionAuth !== 'true') {
        window.location.href = '/pin';
    }
}

// Function for index.html
function checkAccess() {
    const cookies = getCookies();
    const secretCookie = cookies['secret'];
    const encryptCookie = cookies['encrypt'];
    if (secretCookie && encryptCookie) {
        window.location.href = '/';
    } else {
        setTimeout(checkAccess, 5000); // Check again after 5 seconds
    }
}



let ws;

function connectWebSocket() {
    ws = new WebSocket('wss://' + window.location.host);
    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === 'newDevicePrompt') {
            handleNewDevicePrompt(message.ip);
        } else if (message.type === 'deviceResponseUpdate') {
            handleDeviceResponseUpdate(message.ip, message.allow);
        }
    };
    ws.onclose = () => {
        setTimeout(connectWebSocket, 1000); // Reconnect on close
    };
}

function handleNewDevicePrompt(ip) {
    const existingPrompt = document.querySelector(`.new-user-message[data-ip="${ip}"]`);
    if (!existingPrompt) {
        const promptElement = document.createElement('div');
        promptElement.className = 'new-user-message';
        promptElement.setAttribute('data-ip', ip);
        promptElement.innerHTML = `
            <span>Allow user with IP ${ip} to access?</span>
            <button onclick="handleDeviceResponse('${ip}', true)">Allow</button>
            <button onclick="handleDeviceResponse('${ip}', false)">Deny</button>
        `;
        document.body.appendChild(promptElement);
    }
}

function handleDeviceResponse(ip, allow) {
    ws.send(JSON.stringify({ type: 'deviceResponse', ip, allow }));
}

function handleDeviceResponseUpdate(ip, allow) {
    const existingPrompt = document.querySelector(`.new-user-message[data-ip="${ip}"]`);
    if (existingPrompt) {
        existingPrompt.remove();
    }

    if (allow) {
        showNewUserMessage(ip);
    }
}

function showNewUserMessage(ip) {
  const message = document.createElement('div');
  message.className = 'new-user-message';
  message.setAttribute('data-ip', ip);
  message.innerHTML = `
    <span>New user [${ip}] added</span>
    <button onclick="dismissMessage(this.parentElement)">Dismiss</button>
  `;
  message.addEventListener('click', (event) => {
    if (event.target.tagName !== 'BUTTON') {
      promptRemoveUser(ip, message);
    }
  });
  document.body.appendChild(message);
}

function promptRemoveUser(ip, messageElement) {
  const remove = confirm(`Remove user [${ip}]?`);
  if (remove) {
    fetch('/remove-device', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ip: ip }),
      credentials: 'include' // to include cookies
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        messageElement.remove();
        console.log(`Removed user ${ip}`);
      } else {
        console.error(data.message);
      }
    })
    .catch(error => console.error('Error:', error));
  }
}









function dismissMessage(element) {
    element.remove();
}





// Call this function on all pages
document.addEventListener('DOMContentLoaded', function() {
    connectWebSocket();
    if (window.location.pathname.includes('main.html')) {
        checkAccess();
    } else {
        checkSessionAuth();
        setInterval(checkSessionAuth, 3600000);
    }
}, false);
