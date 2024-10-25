let previousSecretFileCount = 0;

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
    
    // Get current secret files count from cookie
    const currentFileCount = parseInt(cookies['secret_count'] || '0');
    
    if (currentFileCount > previousSecretFileCount) {
        showNewUserMessage('New user added');
    }
    previousSecretFileCount = currentFileCount;

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
        setTimeout(checkAccess, 5000);
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
        } else if (message.type === 'newUserCreated') {
            showNewUserMessage(message.ip);
        }
    };
    ws.onclose = () => {
        setTimeout(connectWebSocket, 1000);
    };
}

function handleNewDevicePrompt(ip) {
    const existingPrompt = document.querySelector(`.new-user-message[data-ip="${ip}"]`);
    if (existingPrompt) {
        existingPrompt.remove();
    }
    
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

function handleDeviceResponse(ip, allow) {
    ws.send(JSON.stringify({ type: 'deviceResponse', ip, allow }));
}

function handleDeviceResponseUpdate(ip, allow, isNewUser) {
    const existingPrompt = document.querySelector(`.new-user-message[data-ip="${ip}"]`);
    if (existingPrompt) {
        existingPrompt.remove();
    }

    const message = document.createElement('div');
    message.className = 'new-user-message';
    message.setAttribute('data-ip', ip);
    
    if (allow) {
        message.innerHTML = `
            <span>User [${ip}] was accepted</span>
            <button onclick="dismissMessage(this.parentElement)">Dismiss</button>
        `;
        document.body.appendChild(message);
        setTimeout(() => {
            message.remove();
        }, 3000);
    } else if (!allow) {
        message.innerHTML = `
            <span>User [${ip}] was denied</span>
            <button onclick="dismissMessage(this.parentElement)">Dismiss</button>
        `;
        document.body.appendChild(message);
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
            credentials: 'include'
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

document.addEventListener('DOMContentLoaded', function() {
    connectWebSocket();
    if (window.location.pathname.includes('main.html')) {
        checkAccess();
    } else {
        checkSessionAuth();
        setInterval(checkSessionAuth, 5000); // Changed to check every 5 seconds
    }
}, false);
