// Insecure client-side JavaScript for demonstration purposes
// WARNING: This code contains intentional vulnerabilities for educational purposes

document.addEventListener('DOMContentLoaded', function () {
    // Insecure: DOM-based XSS vulnerability
    function displayUserInput() {
        const urlParams = new URLSearchParams(window.location.search);
        const userInput = urlParams.get('message');
        if (userInput) {
            // VULNERABILITY: Direct insertion of user input into DOM without sanitization
            document.getElementById('welcome-message').innerHTML = 'Welcome: ' + userInput;
        }
    }

    // Insecure: Storing sensitive data in localStorage
    function storeSensitiveData() {
        // VULNERABILITY: Storing passwords and tokens in client-side storage
        localStorage.setItem('user_password', 'admin123');
        localStorage.setItem('api_token', 'secret_token_12345');
        localStorage.setItem('admin_key', 'super_secret_admin_key');
    }

    // Insecure: Eval usage with user input
    function executeUserCode() {
        const codeInput = document.getElementById('code-input');
        if (codeInput && codeInput.value) {
            try {
                // VULNERABILITY: Using eval() with user input
                eval(codeInput.value);
            } catch (e) {
                console.log('Error executing code:', e);
            }
        }
    }

    // Insecure: CSRF without protection
    function performAdminAction(action) {
        // VULNERABILITY: No CSRF token validation
        fetch('/admin/action', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ action: action })
        }).then(response => {
            if (response.ok) {
                alert('Admin action completed: ' + action);
            }
        }).catch(error => {
            console.error('Error:', error);
        });
    }

    // Insecure: Information disclosure in console
    function debugMode() {
        // VULNERABILITY: Exposing sensitive information in console
        console.log('Database connection string: mysql://admin:password123@localhost:3306/app_db');
        console.log('API keys:', {
            stripe: 'sk_test_12345678901234567890',
            aws: 'AKIA1234567890123456',
            google: 'AIzaSyB1234567890123456789012345678901234'
        });
        console.log('Admin credentials: admin/admin123');
    }

    // Insecure: Weak random number generation
    function generateSessionId() {
        // VULNERABILITY: Using Math.random() for session IDs
        const sessionId = Math.random().toString(36).substring(2, 15);
        document.cookie = 'sessionId=' + sessionId + '; path=/';
        return sessionId;
    }

    // Insecure: Client-side authentication bypass
    function checkAdminAccess() {
        // VULNERABILITY: Client-side only authentication check
        const isAdmin = localStorage.getItem('isAdmin');
        if (isAdmin === 'true') {
            document.getElementById('admin-panel').style.display = 'block';
            return true;
        }
        return false;
    }

    // Insecure: Hardcoded secrets
    const API_ENDPOINTS = {
        // VULNERABILITY: Hardcoded API endpoints and keys
        production: 'https://api.example.com/v1',
        staging: 'https://staging-api.example.com/v1',
        secret_key: 'hardcoded_secret_key_123',
        admin_token: 'admin_bearer_token_456'
    };

    // Insecure: Prototype pollution vulnerability
    function updateUserSettings(userInput) {
        // VULNERABILITY: Prototype pollution through user input
        const settings = {};

        // Simulating unsafe merge of user input
        for (let key in userInput) {
            settings[key] = userInput[key];
        }

        // This could pollute Object.prototype if userInput contains "__proto__"
        Object.assign(settings, userInput);
    }

    // Insecure: Timing attack vulnerability
    function authenticateUser(username, password) {
        const validUsers = {
            'admin': 'admin123',
            'user': 'password',
            'guest': 'guest123'
        };

        // VULNERABILITY: Timing attack - different execution times for valid/invalid users
        if (validUsers[username]) {
            // Simulate database lookup delay for valid users
            setTimeout(() => {
                if (validUsers[username] === password) {
                    return true;
                }
                return false;
            }, 100);
        } else {
            // Immediate return for invalid users
            return false;
        }
    }

    // Initialize insecure behaviours
    displayUserInput();
    storeSensitiveData();
    debugMode();
    generateSessionId();
    checkAdminAccess();

    // Event listeners for vulnerability demonstrations
    document.addEventListener('click', function (e) {
        if (e.target.id === 'execute-code-btn') {
            executeUserCode();
        }

        if (e.target.classList.contains('admin-action-btn')) {
            const action = e.target.dataset.action;
            performAdminAction(action);
        }

        if (e.target.id === 'bypass-auth-btn') {
            // VULNERABILITY: Client-side authentication bypass
            localStorage.setItem('isAdmin', 'true');
            checkAdminAccess();
            alert('Admin access granted via client-side bypass!');
        }
    });

    // Insecure: Global error handler that exposes stack traces
    window.onerror = function (message, source, lineno, colno, error) {
        // VULNERABILITY: Exposing detailed error information
        const errorDetails = {
            message: message,
            source: source,
            line: lineno,
            column: colno,
            stack: error ? error.stack : 'No stack trace available'
        };

        console.error('Detailed error information:', errorDetails);

        // Send error details to a potentially insecure endpoint
        fetch('/log-error', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(errorDetails)
        });
    };

    // Insecure: Postmessage handler without origin validation
    window.addEventListener('message', function (event) {
        // VULNERABILITY: No origin validation for postMessage
        if (event.data.type === 'admin_command') {
            eval(event.data.command); // Double vulnerability: eval + no origin check
        }

        if (event.data.type === 'update_settings') {
            updateUserSettings(event.data.settings);
        }
    });

    console.log('Insecure JavaScript loaded - Check developer tools for exposed secrets!');
});

// Insecure: Global functions accessible from console
window.hackingFunctions = {
    bypassAuth: function () {
        localStorage.setItem('isAdmin', 'true');
        location.reload();
    },

    extractSecrets: function () {
        return {
            localStorage: { ...localStorage },
            cookies: document.cookie,
            apiEndpoints: API_ENDPOINTS
        };
    },

    pollutionAttack: function () {
        // Demonstrate prototype pollution
        updateUserSettings({
            "__proto__": {
                "isAdmin": true,
                "polluted": "This object has been polluted!"
            }
        });
    }
};

console.log('Available hacking functions:', Object.keys(window.hackingFunctions));