<?php
session_start();

$conn = new mysqli("localhost", "root", "", "geo_society");

// Initialize variables
$error = "";
$success = "";
$valid_token = false;
$user_id = 0;

// Check if token and user ID are provided
if (isset($_GET['token']) && isset($_GET['user'])) {
    $token = $_GET['token'];
    $user_id = intval($_GET['user']);
    
    // Validate token
    $stmt = $conn->prepare("
        SELECT prt.id, prt.expires_at, prt.used 
        FROM password_reset_tokens prt
        JOIN users u ON prt.user_id = u.id
        WHERE prt.user_id = ? 
        AND u.is_active = 1
        ORDER BY prt.created_at DESC 
        LIMIT 1
    ");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows == 1) {
        $stmt->bind_result($token_id, $expires_at, $used);
        $stmt->fetch();
        
        // Check if token is expired or used
        if (!$used && strtotime($expires_at) > time()) {
            // Get all tokens for this user and verify
            $all_tokens_stmt = $conn->prepare("
                SELECT token_hash FROM password_reset_tokens 
                WHERE user_id = ? AND id = ?
            ");
            $all_tokens_stmt->bind_param("ii", $user_id, $token_id);
            $all_tokens_stmt->execute();
            $all_tokens_stmt->bind_result($token_hash);
            $all_tokens_stmt->fetch();
            $all_tokens_stmt->close();
            
            if (password_verify($token, $token_hash)) {
                $valid_token = true;
                $_SESSION['reset_user_id'] = $user_id;
                $_SESSION['reset_token'] = $token;
            } else {
                $error = "Invalid or expired reset link.";
            }
        } else {
            $error = "This reset link has expired or has already been used.";
        }
    } else {
        $error = "Invalid or expired reset link.";
    }
    $stmt->close();
} elseif ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Handle password reset submission
    if (!isset($_SESSION['reset_user_id']) || !isset($_SESSION['reset_token'])) {
        $error = "Invalid reset session. Please request a new reset link.";
    } else {
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        
        // Validate passwords
        if (empty($password) || empty($confirm_password)) {
            $error = "Please fill in both password fields.";
        } elseif (strlen($password) < 8) {
            $error = "Password must be at least 8 characters long.";
        } elseif (!preg_match('/[A-Z]/', $password)) {
            $error = "Password must contain at least one uppercase letter.";
        } elseif (!preg_match('/[a-z]/', $password)) {
            $error = "Password must contain at least one lowercase letter.";
        } elseif (!preg_match('/[0-9]/', $password)) {
            $error = "Password must contain at least one number.";
        } elseif ($password !== $confirm_password) {
            $error = "Passwords do not match.";
        } else {
            $user_id = $_SESSION['reset_user_id'];
            $token = $_SESSION['reset_token'];
            
            // Verify token again before resetting
            $verify_stmt = $conn->prepare("
                SELECT prt.id FROM password_reset_tokens prt
                WHERE prt.user_id = ? 
                AND prt.used = 0 
                AND prt.expires_at > NOW()
                ORDER BY prt.created_at DESC 
                LIMIT 1
            ");
            $verify_stmt->bind_param("i", $user_id);
            $verify_stmt->execute();
            $verify_stmt->store_result();
            
            if ($verify_stmt->num_rows == 1) {
                $verify_stmt->bind_result($token_id);
                $verify_stmt->fetch();
                
                // Get token hash to verify
                $hash_stmt = $conn->prepare("SELECT token_hash FROM password_reset_tokens WHERE id = ?");
                $hash_stmt->bind_param("i", $token_id);
                $hash_stmt->execute();
                $hash_stmt->bind_result($token_hash);
                $hash_stmt->fetch();
                $hash_stmt->close();
                
                if (password_verify($token, $token_hash)) {
                    // Update password
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    
                    $update_stmt = $conn->prepare("UPDATE users SET password_hash = ?, failed_attempts = 0 WHERE id = ?");
                    $update_stmt->bind_param("si", $password_hash, $user_id);
                    
                    if ($update_stmt->execute()) {
                        // Mark token as used
                        $token_stmt = $conn->prepare("UPDATE password_reset_tokens SET used = 1 WHERE id = ?");
                        $token_stmt->bind_param("i", $token_id);
                        $token_stmt->execute();
                        $token_stmt->close();
                        
                        // Clear reset sessions
                        unset($_SESSION['reset_user_id']);
                        unset($_SESSION['reset_token']);
                        
                        // Log the password reset
                        $log_stmt = $conn->prepare("INSERT INTO password_reset_logs (user_id, ip_address, user_agent, status) VALUES (?, ?, ?, 'success')");
                        $log_stmt->bind_param("iss", $user_id, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
                        $log_stmt->execute();
                        $log_stmt->close();
                        
                        $success = "Password reset successfully! You can now <a href='login.php'>login</a> with your new password.";
                        $valid_token = false; // Hide the form
                    } else {
                        $error = "Error updating password. Please try again.";
                    }
                    $update_stmt->close();
                } else {
                    $error = "Invalid token. Please request a new reset link.";
                }
            } else {
                $error = "Reset link has expired. Please request a new one.";
            }
            $verify_stmt->close();
        }
    }
} else {
    $error = "Invalid reset link.";
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Reset Password | Geo Society</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
}

.container {
    width: 100%;
    max-width: 450px;
    background: rgba(255, 255, 255, 0.95);
    border-radius: 16px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 40px 35px;
    animation: fadeInUp 0.6s ease-out;
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

.header {
    text-align: center;
    margin-bottom: 30px;
}

.logo {
    width: 80px;
    height: 80px;
    margin: 0 auto 15px;
    border-radius: 50%;
    border: 2px dashed #2e7d32;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #2e7d32;
    font-weight: 600;
    background: rgba(46, 125, 50, 0.05);
}

h1 {
    color: #1b5e20;
    margin-bottom: 10px;
    font-size: 24px;
}

.subtitle {
    color: #666;
    font-size: 14px;
    line-height: 1.5;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 8px;
    color: #444;
    font-weight: 500;
    font-size: 14px;
}

input[type="password"] {
    width: 100%;
    padding: 14px 16px;
    border: 2px solid #e0e0e0;
    border-radius: 10px;
    font-size: 14px;
    transition: all 0.3s;
    background: #fafafa;
}

input[type="password"]:focus {
    outline: none;
    border-color: #2e7d32;
    background: #fff;
    box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.1);
}

.password-strength {
    height: 4px;
    background: #eee;
    border-radius: 2px;
    margin-top: 8px;
    overflow: hidden;
}

.strength-bar {
    height: 100%;
    width: 0%;
    transition: width 0.3s, background-color 0.3s;
}

.requirements {
    font-size: 12px;
    color: #666;
    margin-top: 5px;
}

.requirements ul {
    list-style: none;
    padding-left: 5px;
}

.requirements li {
    margin-bottom: 3px;
}

.requirements li.valid {
    color: #2e7d32;
}

.requirements li.invalid {
    color: #dc3545;
}

.btn {
    width: 100%;
    padding: 15px;
    background: linear-gradient(135deg, #2e7d32, #1b5e20);
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s;
    margin-top: 10px;
}

.btn:hover {
    background: linear-gradient(135deg, #1b5e20, #2e7d32);
    transform: translateY(-1px);
    box-shadow: 0 5px 15px rgba(46, 125, 50, 0.3);
}

.btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}

.message {
    padding: 12px 16px;
    margin-bottom: 20px;
    border-radius: 10px;
    font-size: 14px;
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

.error {
    background: linear-gradient(135deg, #ffebee, #ffcdd2);
    color: #c62828;
    border: 1px solid #ff8a80;
}

.success {
    background: linear-gradient(135deg, #e8f5e9, #c8e6c9);
    color: #2e7d32;
    border: 1px solid #a5d6a7;
}

.links {
    margin-top: 25px;
    text-align: center;
    font-size: 14px;
}

.links a {
    color: #2e7d32;
    text-decoration: none;
    font-weight: 500;
    transition: color 0.3s;
}

.links a:hover {
    color: #1b5e20;
    text-decoration: underline;
}

.footer {
    margin-top: 25px;
    padding-top: 15px;
    border-top: 1px solid #eee;
    text-align: center;
    color: #888;
    font-size: 12px;
}

@media (max-width: 480px) {
    .container {
        padding: 25px 20px;
        margin: 10px;
    }
}
</style>
</head>
<body>

<div class="container">
    <div class="header">
        <div class="logo">GEO<br>SOCIETY</div>
        <h1>Set New Password</h1>
        <p class="subtitle">Create a strong, secure password for your account.</p>
    </div>

    <?php if($error && !$valid_token): ?>
        <div class="message error"><?php echo htmlspecialchars($error); ?></div>
        <div class="links">
            <a href="forgot_password.php">Request a new reset link</a>
            <span style="color: #ddd; margin: 0 10px;">•</span>
            <a href="login.php">Back to Login</a>
        </div>
    <?php elseif($success): ?>
        <div class="message success"><?php echo $success; ?></div>
        <div class="links">
            <a href="login.php">Go to Login Page</a>
        </div>
    <?php elseif($valid_token): ?>
        <?php if($error): ?>
            <div class="message error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <form method="post" id="resetPasswordForm">
            <div class="form-group">
                <label for="password">New Password</label>
                <input type="password" 
                       id="password" 
                       name="password" 
                       placeholder="Enter new password"
                       required
                       minlength="8">
                <div class="password-strength">
                    <div class="strength-bar" id="strengthBar"></div>
                </div>
                <div class="requirements">
                    <ul>
                        <li id="req-length" class="invalid">At least 8 characters</li>
                        <li id="req-uppercase" class="invalid">One uppercase letter</li>
                        <li id="req-lowercase" class="invalid">One lowercase letter</li>
                        <li id="req-number" class="invalid">One number</li>
                    </ul>
                </div>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm New Password</label>
                <input type="password" 
                       id="confirm_password" 
                       name="confirm_password" 
                       placeholder="Confirm new password"
                       required
                       minlength="8">
                <div id="confirmMessage" style="font-size: 12px; margin-top: 5px;"></div>
            </div>

            <button type="submit" class="btn" id="submitBtn" disabled>Reset Password</button>
        </form>

        <div class="links">
            <a href="login.php">← Back to Login</a>
        </div>
    <?php endif; ?>

    <div class="footer">
        © <?php echo date('Y'); ?> Geo Society – University of Malawi<br>
        <small>Secure Password Reset • Privacy Protected</small>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('resetPasswordForm');
    const passwordInput = document.getElementById('password');
    const confirmInput = document.getElementById('confirm_password');
    const submitBtn = document.getElementById('submitBtn');
    const strengthBar = document.getElementById('strengthBar');
    
    if (form) {
        // Password strength checker
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            
            // Check requirements
            const hasLength = password.length >= 8;
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            
            // Update requirement indicators
            document.getElementById('req-length').className = hasLength ? 'valid' : 'invalid';
            document.getElementById('req-uppercase').className = hasUpper ? 'valid' : 'invalid';
            document.getElementById('req-lowercase').className = hasLower ? 'valid' : 'invalid';
            document.getElementById('req-number').className = hasNumber ? 'valid' : 'invalid';
            
            // Calculate strength
            if (hasLength) strength += 25;
            if (hasUpper) strength += 25;
            if (hasLower) strength += 25;
            if (hasNumber) strength += 25;
            
            // Update strength bar
            strengthBar.style.width = strength + '%';
            
            if (strength < 50) {
                strengthBar.style.backgroundColor = '#dc3545';
            } else if (strength < 75) {
                strengthBar.style.backgroundColor = '#ffc107';
            } else {
                strengthBar.style.backgroundColor = '#28a745';
            }
            
            validateForm();
        });
        
        // Confirm password checker
        confirmInput.addEventListener('input', function() {
            validateForm();
        });
        
        function validateForm() {
            const password = passwordInput.value;
            const confirm = confirmInput.value;
            const confirmMessage = document.getElementById('confirmMessage');
            let isValid = true;
            
            // Check all requirements
            const hasLength = password.length >= 8;
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            const hasNumber = /[0-9]/.test(password);
            const passwordsMatch = password === confirm && password !== '';
            
            // Update confirm message
            if (confirm === '') {
                confirmMessage.textContent = '';
                confirmMessage.style.color = '';
            } else if (passwordsMatch) {
                confirmMessage.textContent = '✓ Passwords match';
                confirmMessage.style.color = '#28a745';
            } else {
                confirmMessage.textContent = '✗ Passwords do not match';
                confirmMessage.style.color = '#dc3545';
                isValid = false;
            }
            
            // Check all requirements
            if (!hasLength || !hasUpper || !hasLower || !hasNumber) {
                isValid = false;
            }
            
            // Enable/disable submit button
            submitBtn.disabled = !isValid;
            
            return isValid;
        }
        
        // Form submission
        form.addEventListener('submit', function(e) {
            if (!validateForm()) {
                e.preventDefault();
                alert('Please fix the errors before submitting.');
                return;
            }
            
            // Show loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = 'Resetting...';
            submitBtn.style.opacity = '0.7';
        });
        
        // Initialize validation
        validateForm();
    }
});
</script>

</body>
</html>