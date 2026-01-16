<?php
session_start();

// Security: Prevent session fixation
session_regenerate_id(true);

// Initialize variables
$identifier = $password = "";
$error = "";
$login_attempts = $_SESSION['login_attempts'] ?? 0;
$lockout_time = $_SESSION['lockout_time'] ?? 0;

// Check if user is already logged in
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

// Check for account creation success message
if (isset($_SESSION['success'])) {
    $success_message = $_SESSION['success'];
    unset($_SESSION['success']);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Check for lockout
    if ($lockout_time > time()) {
        $remaining = ceil(($lockout_time - time()) / 60);
        $error = "Too many failed attempts. Please try again in $remaining minute(s).";
    } else {
        // Reset lockout if time has passed
        if ($lockout_time > 0 && $lockout_time <= time()) {
            $_SESSION['login_attempts'] = 0;
            $_SESSION['lockout_time'] = 0;
            $login_attempts = 0;
        }
        
        $conn = new mysqli("localhost", "root", "", "geo_society");
        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

        // Sanitize and validate input
        $identifier = trim($_POST['identifier']);
        $password = $_POST['password'];
        $remember = isset($_POST['remember']) ? true : false;

        // Validate input
        if (empty($identifier) || empty($password)) {
            $error = "Please enter both email/student ID and password.";
        } else {
            // Check if identifier is email or student ID
            $is_email = filter_var($identifier, FILTER_VALIDATE_EMAIL);
            $is_student_id = preg_match("/^(BSC-GEO|BED-GEO|BSC-GLY)-\d{2}-\d{2}$/i", $identifier);
            
            if (!$is_email && !$is_student_id) {
                $error = "Please enter a valid email or student ID.";
            } else {
                // Normalize identifier
                if ($is_email) {
                    $identifier = strtolower($identifier);
                } else {
                    $identifier = strtoupper($identifier);
                }
                
                // Prepare query - only check active accounts
                $stmt = $conn->prepare("SELECT id, full_name, student_id, email, password_hash, is_active, failed_attempts, last_login FROM users WHERE (email=? OR student_id=?) AND is_active=1 LIMIT 1");
                $stmt->bind_param("ss", $identifier, $identifier);
                $stmt->execute();
                $stmt->store_result();
                
                if ($stmt->num_rows == 1) {
                    $stmt->bind_result($id, $full_name, $student_id, $email, $password_hash, $is_active, $failed_attempts, $last_login);
                    $stmt->fetch();
                    
                    // Verify password
                    if (password_verify($password, $password_hash)) {
                        // Login successful - reset failed attempts
                        $update_stmt = $conn->prepare("UPDATE users SET failed_attempts=0, last_login=NOW() WHERE id=?");
                        $update_stmt->bind_param("i", $id);
                        $update_stmt->execute();
                        $update_stmt->close();
                        
                        // Reset session login attempts
                        $_SESSION['login_attempts'] = 0;
                        $_SESSION['lockout_time'] = 0;
                        
                        // Set session variables
                        $_SESSION['user_id'] = $id;
                        $_SESSION['full_name'] = $full_name;
                        $_SESSION['student_id'] = $student_id;
                        $_SESSION['email'] = $email;
                        $_SESSION['logged_in'] = time();
                        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                        
                        // Set remember me cookie if requested
                        if ($remember) {
                            $token = bin2hex(random_bytes(32));
                            $expiry = time() + (30 * 24 * 60 * 60); // 30 days
                            
                            // Store token in database
                            $token_hash = password_hash($token, PASSWORD_DEFAULT);
                            
                            // First check if remember_tokens table exists
                            $table_check = $conn->query("SHOW TABLES LIKE 'remember_tokens'");
                            if ($table_check->num_rows > 0) {
                                $stmt_token = $conn->prepare("INSERT INTO remember_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)");
                                $expiry_date = date('Y-m-d H:i:s', $expiry);
                                $stmt_token->bind_param("iss", $id, $token_hash, $expiry_date);
                                $stmt_token->execute();
                                $stmt_token->close();
                                
                                // Set cookie
                                setcookie('remember_token', $token, $expiry, '/', '', true, true);
                                setcookie('user_id', $id, $expiry, '/', '', true, true);
                            }
                        }
                        
                        // Log successful login (optional) - with error handling
                        try {
                            // Check if login_logs table exists
                            $table_check = $conn->query("SHOW TABLES LIKE 'login_logs'");
                            if ($table_check->num_rows > 0) {
                                $log_stmt = $conn->prepare("INSERT INTO login_logs (user_id, ip_address, user_agent, status) VALUES (?, ?, ?, 'success')");
                                $log_stmt->bind_param("iss", $id, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
                                $log_stmt->execute();
                                $log_stmt->close();
                            }
                        } catch (Exception $e) {
                            // Silently fail - don't interrupt login for missing log table
                            error_log("Login logging failed: " . $e->getMessage());
                        }
                        
                        $stmt->close();
                        $conn->close();
                        
                        // Redirect to dashboard
                        header("Location: dashboard.php");
                        exit();
                    } else {
                        // Incorrect password - increment failed attempts
                        $new_attempts = $failed_attempts + 1;
                        $update_stmt = $conn->prepare("UPDATE users SET failed_attempts=? WHERE id=?");
                        $update_stmt->bind_param("ii", $new_attempts, $id);
                        $update_stmt->execute();
                        $update_stmt->close();
                        
                        // Increment session attempts
                        $_SESSION['login_attempts'] = ++$login_attempts;
                        
                        // Apply lockout after 5 attempts
                        if ($login_attempts >= 5) {
                            $_SESSION['lockout_time'] = time() + (15 * 60); // 15 minutes lockout
                            $error = "Too many failed attempts. Account locked for 15 minutes.";
                        } else {
                            $remaining = 5 - $login_attempts;
                            $error = "Incorrect password. {$remaining} attempt(s) remaining.";
                        }
                        
                        // Log failed attempt with error handling
                        try {
                            // Check if login_logs table exists
                            $table_check = $conn->query("SHOW TABLES LIKE 'login_logs'");
                            if ($table_check->num_rows > 0) {
                                $log_stmt = $conn->prepare("INSERT INTO login_logs (user_id, ip_address, user_agent, status) VALUES (?, ?, ?, 'failed')");
                                $log_stmt->bind_param("iss", $id, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
                                $log_stmt->execute();
                                $log_stmt->close();
                            }
                        } catch (Exception $e) {
                            // Silently fail - don't show error to user
                            error_log("Failed login logging error: " . $e->getMessage());
                        }
                    }
                } else {
                    // User not found or inactive
                    $error = "Invalid credentials or account inactive.";
                    
                    // Increment session attempts for non-existent users too
                    $_SESSION['login_attempts'] = ++$login_attempts;
                    
                    if ($login_attempts >= 5) {
                        $_SESSION['lockout_time'] = time() + (15 * 60);
                        $error = "Too many failed attempts. Please try again in 15 minutes.";
                    }
                }
                $stmt->close();
            }
        }
        $conn->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login | Geo Society – University of Malawi</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<!-- Security headers -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self';">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta http-equiv="X-Frame-Options" content="DENY">
<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: "Segoe UI", Arial, sans-serif;
}

body {
    min-height: 100vh;
    background: linear-gradient(135deg, #1b5e20, #2e7d32, #4caf50);
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 20px;
    position: relative;
    overflow-x: hidden;
}

/* Animated background elements */
body::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: 
        radial-gradient(circle at 20% 80%, rgba(255,255,255,0.1) 0%, transparent 50%),
        radial-gradient(circle at 80% 20%, rgba(255,255,255,0.05) 0%, transparent 50%);
    z-index: 0;
}

.login-container {
    width: 100%;
    max-width: 400px;
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border-radius: 16px;
    box-shadow: 
        0 20px 40px rgba(0, 0, 0, 0.1),
        0 0 0 1px rgba(255, 255, 255, 0.1) inset;
    padding: 35px 30px;
    position: relative;
    z-index: 1;
    animation: fadeInUp 0.6s ease-out;
    border: 1px solid rgba(46, 125, 50, 0.1);
}

@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.logo-box {
    width: 120px;
    height: 120px;
    margin: 0 auto 20px;
    border-radius: 50%;
    border: 3px dashed #2e7d32;
    display: flex;
    justify-content: center;
    align-items: center;
    color: #2e7d32;
    font-weight: 600;
    text-align: center;
    font-size: 14px;
    background: rgba(46, 125, 50, 0.05);
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.02); }
}

h2 {
    text-align: center;
    color: #1b5e20;
    margin-bottom: 8px;
    font-size: 24px;
    font-weight: 700;
    background: linear-gradient(135deg, #1b5e20, #2e7d32);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.subtitle {
    text-align: center;
    font-size: 14px;
    color: #666;
    margin-bottom: 25px;
    line-height: 1.4;
}

.form-group {
    margin-bottom: 18px;
    position: relative;
}

label {
    font-size: 13px;
    color: #444;
    display: block;
    margin-bottom: 6px;
    font-weight: 500;
}

input[type="text"],
input[type="password"] {
    width: 100%;
    padding: 14px 16px;
    border-radius: 10px;
    border: 2px solid #e0e0e0;
    outline: none;
    font-size: 14px;
    background: #fafafa;
    transition: all 0.3s ease;
    padding-right: 50px; /* Make room for the toggle */
}

input[type="text"]:focus,
input[type="password"]:focus {
    border-color: #2e7d32;
    background: #fff;
    box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.1);
}

input[type="text"]:hover,
input[type="password"]:hover {
    border-color: #bdbdbd;
}

/* Show password toggle */
.password-wrapper {
    position: relative;
}

.password-toggle {
    position: absolute;
    right: 15px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: #666;
    cursor: pointer;
    font-size: 12px;
    padding: 8px 12px;
    z-index: 10;
    pointer-events: auto;
    user-select: none;
    outline: none;
    border-radius: 4px;
    transition: all 0.2s ease;
}

.password-toggle:hover {
    color: #2e7d32;
    background: rgba(46, 125, 50, 0.1);
}

.password-toggle:active {
    background: rgba(46, 125, 50, 0.2);
}

/* Remember me checkbox */
.remember-group {
    display: flex;
    align-items: center;
    margin-bottom: 20px;
}

.remember-group input[type="checkbox"] {
    margin-right: 8px;
    width: 16px;
    height: 16px;
    accent-color: #2e7d32;
}

.remember-group label {
    margin: 0;
    font-size: 13px;
    color: #555;
    cursor: pointer;
}

.login-btn {
    width: 100%;
    padding: 15px;
    margin-top: 10px;
    background: linear-gradient(135deg, #2e7d32, #1b5e20);
    color: #fff;
    border: none;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.login-btn:hover {
    background: linear-gradient(135deg, #1b5e20, #2e7d32);
    transform: translateY(-1px);
    box-shadow: 0 5px 15px rgba(46, 125, 50, 0.3);
}

.login-btn:active {
    transform: translateY(0);
}

.login-btn:disabled {
    background: #cccccc;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
}

/* Loading animation */
.login-btn.loading::after {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 20px;
    height: 20px;
    margin: -10px 0 0 -10px;
    border: 2px solid #fff;
    border-top-color: transparent;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

.links {
    margin-top: 20px;
    text-align: center;
    font-size: 13px;
    display: flex;
    justify-content: center;
    gap: 15px;
    flex-wrap: wrap;
}

.links a {
    color: #2e7d32;
    text-decoration: none;
    font-weight: 500;
    transition: all 0.3s ease;
    position: relative;
    padding: 2px 0;
}

.links a:hover {
    color: #1b5e20;
    text-decoration: none;
}

.links a::after {
    content: '';
    position: absolute;
    bottom: 0;
    left: 0;
    width: 0;
    height: 1px;
    background: #2e7d32;
    transition: width 0.3s ease;
}

.links a:hover::after {
    width: 100%;
}

.footer-text {
    margin-top: 25px;
    text-align: center;
    font-size: 12px;
    color: #888;
    padding-top: 15px;
    border-top: 1px solid #eee;
}

/* Message boxes */
.message-box {
    padding: 12px 16px;
    margin-bottom: 20px;
    border-radius: 10px;
    font-size: 13px;
    animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateX(-10px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

.error-box {
    background: linear-gradient(135deg, #ffebee, #ffcdd2);
    color: #c62828;
    border: 1px solid #ff8a80;
}

.success-box {
    background: linear-gradient(135deg, #e8f5e9, #c8e6c9);
    color: #2e7d32;
    border: 1px solid #a5d6a7;
}

/* Lockout warning */
.lockout-warning {
    background: #fff3e0;
    color: #ef6c00;
    border: 1px solid #ffb74d;
    padding: 10px;
    border-radius: 8px;
    margin-bottom: 15px;
    font-size: 12px;
    text-align: center;
}

/* Responsive design */
@media (max-width: 480px) {
    .login-container {
        padding: 25px 20px;
        margin: 10px;
    }
    
    .logo-box {
        width: 100px;
        height: 100px;
        font-size: 13px;
    }
    
    h2 {
        font-size: 22px;
    }
    
    .links {
        flex-direction: column;
        gap: 10px;
    }
}

/* Accessibility */
input:focus-visible {
    outline: 2px solid #2e7d32;
    outline-offset: 2px;
}

@media (prefers-reduced-motion: reduce) {
    .login-container,
    .logo-box,
    .message-box {
        animation: none;
    }
    
    .login-btn:hover {
        transform: none;
    }
}
</style>
</head>
<body>

<div class="login-container">

    <div class="logo-box">GEO SOCIETY<br>LOGO</div>
    <h2>Welcome Back</h2>
    <p class="subtitle">Geo Society Portal – University of Malawi</p>

    <?php if(isset($success_message)): ?>
        <div class="message-box success-box">
            <?php echo htmlspecialchars($success_message); ?>
        </div>
    <?php endif; ?>

    <?php if($error): ?>
        <div class="message-box error-box">
            <?php echo htmlspecialchars($error); ?>
        </div>
    <?php endif; ?>

    <?php if(isset($_SESSION['lockout_time']) && $_SESSION['lockout_time'] > time()): ?>
        <div class="lockout-warning">
            ⚠️ Account temporarily locked. Please try again later.
        </div>
    <?php endif; ?>

    <form method="post" id="loginForm" autocomplete="off">
        <div class="form-group">
            <label for="identifier">Email or Student ID</label>
            <input type="text" 
                   name="identifier" 
                   id="identifier"
                   placeholder="Enter your email or student ID" 
                   required 
                   value="<?php echo htmlspecialchars($identifier); ?>"
                   autocomplete="username"
                   <?php echo ($lockout_time > time()) ? 'disabled' : ''; ?>>
            <div class="hint" style="font-size: 11px; color: #777; margin-top: 4px;">
                Student ID format: BSC-GEO-YY-YY
            </div>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <div class="password-wrapper">
                <input type="password" 
                       name="password" 
                       id="password"
                       placeholder="Enter your password" 
                       required
                       autocomplete="current-password"
                       <?php echo ($lockout_time > time()) ? 'disabled' : ''; ?>>
                <!-- ULTIMATE FIX: Using span instead of button -->
                <span class="password-toggle" id="togglePasswordBtn">Show</span>
            </div>
        </div>

        <div class="remember-group">
            <input type="checkbox" name="remember" id="remember" value="1">
            <label for="remember">Remember me for 30 days</label>
        </div>

        <button class="login-btn" 
                type="submit" 
                id="submitBtn"
                <?php echo ($lockout_time > time()) ? 'disabled' : ''; ?>>
            Login
        </button>
    </form>

    <div class="links">
        <a href="forgot_password.php">Forgot Password?</a>  <!-- Update this line -->
        <span style="color: #ddd;">•</span>
        <a href="create_account.php">Create New Account</a>
        <span style="color: #ddd;">•</span>
        <a href="help.php">Need Help?</a>
    </div>

    <div class="footer-text">
        © <?php echo date('Y'); ?> Geo Society – University of Malawi
        <div style="font-size: 11px; margin-top: 5px; color: #aaa;">
            Secure Login • Privacy Protected
        </div>
    </div>

</div>

<script>
// ULTIMATE FIX - Simple and reliable
document.addEventListener('DOMContentLoaded', function() {
    // Get elements
    const passwordInput = document.getElementById('password');
    const toggleBtn = document.getElementById('togglePasswordBtn');
    
    // Debug logging to check if elements exist
    console.log('Password input found:', !!passwordInput);
    console.log('Toggle button found:', !!toggleBtn);
    
    // Add click event to toggle password visibility
    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener('click', function() {
            console.log('Toggle button clicked!');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                this.textContent = 'Hide';
                console.log('Password shown');
            } else {
                passwordInput.type = 'password';
                this.textContent = 'Show';
                console.log('Password hidden');
            }
            
            // Keep focus on password field
            passwordInput.focus();
        });
        
        // Also add hover effect
        toggleBtn.addEventListener('mouseenter', function() {
            this.style.color = '#2e7d32';
        });
        
        toggleBtn.addEventListener('mouseleave', function() {
            this.style.color = '#666';
        });
    } else {
        console.error('Password toggle elements not found!');
        if (!passwordInput) console.error('Password input with id="password" not found');
        if (!toggleBtn) console.error('Toggle button with id="togglePasswordBtn" not found');
    }
    
    // Rest of your existing JavaScript code
    const form = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
    const identifierInput = document.getElementById('identifier');
    
    // Form submission handling
    form.addEventListener('submit', function(e) {
        // Client-side validation
        const identifier = identifierInput.value.trim();
        const password = passwordInput.value.trim();
        
        if (!identifier || !password) {
            e.preventDefault();
            alert('Please fill in all required fields.');
            return;
        }
        
        // Show loading state
        submitBtn.disabled = true;
        submitBtn.classList.add('loading');
        submitBtn.innerHTML = 'Logging in...';
        
        // Prevent double submission
        form.dataset.submitted = 'true';
    });
    
    // Auto-capitalize student ID
    identifierInput.addEventListener('input', function() {
        const value = this.value;
        const studentIdPattern = /^(BSC-GEO|BED-GEO|BSC-GLY)/i;
        
        if (studentIdPattern.test(value)) {
            this.value = value.toUpperCase();
        }
    });
    
    // Auto-lowercase email
    identifierInput.addEventListener('blur', function() {
        const value = this.value;
        if (value.includes('@')) {
            this.value = value.toLowerCase();
        }
    });
    
    // Clear error on input
    identifierInput.addEventListener('input', clearError);
    passwordInput.addEventListener('input', clearError);
    
    function clearError() {
        const errorBox = document.querySelector('.error-box');
        if (errorBox) {
            errorBox.style.display = 'none';
        }
    }
    
    // Prevent form resubmission on page refresh
    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
    
    // Focus on first input field
    identifierInput.focus();
    
    // Auto-submit prevention for locked form
    const lockoutTime = <?php echo $lockout_time; ?>;
    const currentTime = Math.floor(Date.now() / 1000);
    
    if (lockoutTime > currentTime) {
        // Disable form and show countdown
        disableFormWithCountdown(lockoutTime - currentTime);
    }
    
    function disableFormWithCountdown(seconds) {
        const minutes = Math.ceil(seconds / 60);
        const countdownElement = document.createElement('div');
        countdownElement.className = 'lockout-warning';
        countdownElement.innerHTML = `⏳ Login disabled. Please try again in ${minutes} minute(s).`;
        
        const form = document.getElementById('loginForm');
        form.parentNode.insertBefore(countdownElement, form);
        
        // Update countdown every minute
        const interval = setInterval(function() {
            seconds -= 60;
            if (seconds <= 0) {
                clearInterval(interval);
                location.reload();
            } else {
                const minutes = Math.ceil(seconds / 60);
                countdownElement.innerHTML = `⏳ Login disabled. Please try again in ${minutes} minute(s).`;
            }
        }, 60000);
    }
});

// Alternative simple function as backup
window.togglePassword = function() {
    const passwordInput = document.getElementById('password');
    const toggleBtn = document.getElementById('togglePasswordBtn');
    
    if (passwordInput && toggleBtn) {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.textContent = 'Hide';
        } else {
            passwordInput.type = 'password';
            toggleBtn.textContent = 'Show';
        }
        passwordInput.focus();
    }
};
</script>

</body>
</html>