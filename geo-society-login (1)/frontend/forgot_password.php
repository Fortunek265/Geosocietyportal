<?php
session_start();
session_regenerate_id(true);

// Initialize variables
$email = "";
$error = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    
    if (empty($email)) {
        $error = "Please enter your email address.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address.";
    } else {
        // Database connection - same as login.php
        $conn = new mysqli("localhost", "root", "", "geo_society");
        
        if ($conn->connect_error) {
            $error = "System temporarily unavailable. Please try again later.";
            error_log("Database connection failed: " . $conn->connect_error);
        } else {
            // Check if email exists
            $stmt = $conn->prepare("SELECT id, full_name, email, is_active FROM users WHERE email = ? AND is_active = 1");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            
            if ($stmt->num_rows == 1) {
                $stmt->bind_result($user_id, $full_name, $user_email, $is_active);
                $stmt->fetch();
                
                // Generate password reset token
                $token = bin2hex(random_bytes(32));
                $token_hash = password_hash($token, PASSWORD_DEFAULT);
                $expires_at = date('Y-m-d H:i:s', strtotime('+1 hour')); // Token valid for 1 hour
                
                // Store token in database
                // Check if password_resets table exists
                $table_check = $conn->query("SHOW TABLES LIKE 'password_resets'");
                
                if ($table_check->num_rows > 0) {
                    // Delete any existing tokens for this user
                    $delete_stmt = $conn->prepare("DELETE FROM password_resets WHERE user_id = ?");
                    $delete_stmt->bind_param("i", $user_id);
                    $delete_stmt->execute();
                    $delete_stmt->close();
                    
                    // Insert new token
                    $insert_stmt = $conn->prepare("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)");
                    $insert_stmt->bind_param("iss", $user_id, $token_hash, $expires_at);
                    $insert_stmt->execute();
                    $insert_stmt->close();
                    
                    // Create reset link (you'll need to update the URL)
                    $reset_link = "http://" . $_SERVER['HTTP_HOST'] . "/geosociety/reset_password.php?token=" . $token . "&email=" . urlencode($email);
                    
                    // TODO: Send email with reset link
                    // For now, just show the link (remove this in production)
                    $success = "Password reset link: <a href='$reset_link'>Click here to reset password</a><br><br>";
                    $success .= "<small>In production, this link would be sent to your email.</small>";
                    
                    // Log the request
                    error_log("Password reset requested for user: $user_id, email: $email");
                } else {
                    $error = "Password reset functionality is not properly configured. Please contact support.";
                }
                
            } else {
                // Don't reveal if email exists or not (security best practice)
                $success = "If your email exists in our system, you will receive a password reset link shortly.";
            }
            
            $stmt->close();
            $conn->close();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password | Geo Society</title>
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
            padding: 35px 30px;
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
        
        h2 {
            text-align: center;
            color: #1b5e20;
            margin-bottom: 20px;
        }
        
        .message-box {
            padding: 12px 16px;
            margin-bottom: 20px;
            border-radius: 10px;
            font-size: 14px;
        }
        
        .error-box {
            background: #ffebee;
            color: #c62828;
            border: 1px solid #ff8a80;
        }
        
        .success-box {
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #a5d6a7;
        }
        
        .info-box {
            background: #e3f2fd;
            color: #1565c0;
            border: 1px solid #90caf9;
            margin-bottom: 20px;
            font-size: 13px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #444;
            font-weight: 500;
        }
        
        input[type="email"] {
            width: 100%;
            padding: 14px 16px;
            border-radius: 10px;
            border: 2px solid #e0e0e0;
            outline: none;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        input[type="email"]:focus {
            border-color: #2e7d32;
            box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.1);
        }
        
        .submit-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #2e7d32, #1b5e20);
            color: #fff;
            border: none;
            border-radius: 10px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .submit-btn:hover {
            background: linear-gradient(135deg, #1b5e20, #2e7d32);
            transform: translateY(-1px);
        }
        
        .links {
            margin-top: 20px;
            text-align: center;
            font-size: 13px;
        }
        
        .links a {
            color: #2e7d32;
            text-decoration: none;
            font-weight: 500;
        }
        
        .links a:hover {
            text-decoration: underline;
        }
        
        .back-link {
            display: inline-block;
            margin-top: 15px;
            color: #666;
            text-decoration: none;
            font-size: 13px;
        }
        
        .back-link:hover {
            color: #2e7d32;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Forgot Password</h2>
        
        <div class="info-box">
            Enter your email address and we'll send you a link to reset your password.
        </div>
        
        <?php if($error): ?>
            <div class="message-box error-box">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <?php if($success): ?>
            <div class="message-box success-box">
                <?php echo $success; ?>
            </div>
        <?php endif; ?>
        
        <?php if(!$success): ?>
            <form method="post" action="">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" 
                           name="email" 
                           id="email" 
                           placeholder="Enter your registered email" 
                           required 
                           value="<?php echo htmlspecialchars($email); ?>"
                           autocomplete="email">
                </div>
                
                <button type="submit" class="submit-btn">Send Reset Link</button>
            </form>
        <?php endif; ?>
        
        <div class="links">
            <a href="login.php">Back to Login</a>
            <span style="margin: 0 10px; color: #ddd;">•</span>
            <a href="create_account.php">Create New Account</a>
        </div>
        
        <?php if($success): ?>
            <a href="login.php" class="back-link">← Return to login page</a>
        <?php endif; ?>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form');
            const emailInput = document.getElementById('email');
            
            if (emailInput) {
                emailInput.focus();
                
                form.addEventListener('submit', function(e) {
                    const email = emailInput.value.trim();
                    
                    if (!email) {
                        e.preventDefault();
                        alert('Please enter your email address.');
                        return;
                    }
                    
                    // Basic email validation
                    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                    if (!emailRegex.test(email)) {
                        e.preventDefault();
                        alert('Please enter a valid email address.');
                        return;
                    }
                });
            }
            
            // Prevent form resubmission
            if (window.history.replaceState) {
                window.history.replaceState(null, null, window.location.href);
            }
        });
    </script>
</body>
</html>