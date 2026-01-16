<?php
// Start session
session_start();

// Generate CSRF token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Define variables
$full_name = $student_id = $email = $year = $password = $confirm_password = "";
$errors = [];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $errors[] = "Security token invalid. Please try again.";
    } else {
        // Connect to MySQL with error handling
        $conn = new mysqli("localhost", "root", "", "geo_society");
        if ($conn->connect_error) {
            die("Connection failed: " . $conn->connect_error);
        }

        // Sanitize and validate inputs
        $full_name = trim(filter_input(INPUT_POST, "full_name", FILTER_SANITIZE_STRING));
        $student_id = strtoupper(trim($_POST["student_id"]));
        $year = $_POST["year"];
        $password = $_POST["password"];
        $confirm_password = $_POST["confirm_password"];
        
        // Validate Year selection
        $valid_years = ["Year 1", "Year 2", "Year 3", "Year 4"];
        if (!in_array($year, $valid_years)) {
            $errors[] = "Please select a valid year of study.";
        }
        
        // Validate Full Name (allow letters, spaces, and hyphens)
        if (!preg_match("/^[a-zA-Z\s\-']{2,50}$/", $full_name)) {
            $errors[] = "Full name must be 2-50 characters and contain only letters, spaces, and hyphens.";
        }

        // Validate Student ID
        $idPattern = "/^(BSC-GEO|BED-GEO|BSC-GLY)-\d{2}-\d{2}$/";
        if (!preg_match($idPattern, $student_id)) {
            $errors[] = "Invalid Student ID format. Examples: BSC-GEO-19-24, BED-GEO-20-25, BSC-GLY-21-26";
        }
        
        // Extract year from Student ID for additional validation
        if (preg_match($idPattern, $student_id)) {
            $parts = explode('-', $student_id);
            $entry_year = $parts[2];
            $current_year = date('y');
            
            // Basic year validation (entry year shouldn't be in future)
            if ($entry_year > $current_year) {
                $errors[] = "Entry year in Student ID appears to be in the future.";
            }
        }

        // Validate password strength
        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters.";
        }
        
        if (!preg_match("/[A-Z]/", $password)) {
            $errors[] = "Password must contain at least one uppercase letter.";
        }
        
        if (!preg_match("/[a-z]/", $password)) {
            $errors[] = "Password must contain at least one lowercase letter.";
        }
        
        if (!preg_match("/[0-9]/", $password)) {
            $errors[] = "Password must contain at least one number.";
        }

        if ($password !== $confirm_password) {
            $errors[] = "Passwords do not match.";
        }

        // Generate email from validated student ID
        if (empty($errors)) {
            $email = strtolower($student_id . "@unima.ac.mw");
            
            // Validate email format
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = "Invalid email generated. Please check your Student ID.";
            }
        }

        // Check for duplicates only if no errors so far
        if (empty($errors)) {
            $stmt = $conn->prepare("SELECT id FROM users WHERE student_id=? OR email=?");
            $stmt->bind_param("ss", $student_id, $email);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows > 0) {
                $errors[] = "Student ID or email already exists. If this is your account, please login instead.";
            }
            $stmt->close();
        }

        // Insert if no errors
        if (empty($errors)) {
            $password_hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO users (full_name, student_id, email, year_of_study, password_hash, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("sssss", $full_name, $student_id, $email, $year, $password_hash);
            
            if ($stmt->execute()) {
                // Regenerate CSRF token after successful submission
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                $_SESSION['success'] = "Account created successfully! You can now login.";
                header("Location: login.php");
                exit();
            } else {
                // Log error for debugging (in production, log to file instead)
                error_log("Registration error: " . $stmt->error);
                $errors[] = "Registration failed due to a system error. Please try again later.";
            }
            $stmt->close();
        }

        $conn->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Create Account | Geo Society – University of Malawi</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:"Segoe UI",Arial,sans-serif;}
body{min-height:100vh;background:linear-gradient(135deg,#1b5e20,#2e7d32,#4caf50);display:flex;justify-content:center;align-items:center;padding:20px;}
.register-container{width:100%;max-width:450px;background:#fff;border-radius:16px;box-shadow:0 18px 40px rgba(0,0,0,0.25);padding:30px 26px;animation:fadeInUp 0.8s ease;}
@keyframes fadeInUp{from{opacity:0;transform:translateY(30px);}to{opacity:1;transform:translateY(0);}}
.logo-box{width:110px;height:110px;margin:0 auto 15px;border-radius:50%;border:3px dashed #2e7d32;display:flex;justify-content:center;align-items:center;color:#2e7d32;font-weight:600;font-size:14px;text-align:center;}
h2{text-align:center;color:#1b5e20;margin-bottom:5px;}
.subtitle{text-align:center;font-size:14px;color:#555;margin-bottom:22px;}
.form-group{margin-bottom:14px;}
label{font-size:13px;color:#333;display:block;margin-bottom:5px;font-weight:500;}
input, select{width:100%;padding:12px;border-radius:8px;border:1px solid #ccc;outline:none;font-size:14px;transition:border-color 0.3s;}
input:focus, select:focus{border-color:#2e7d32;box-shadow:0 0 0 2px rgba(46,125,50,0.15);}
.hint{font-size:12px;color:#777;margin-top:3px;}
.register-btn{width:100%;padding:13px;margin-top:10px;background:#2e7d32;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background 0.3s;}
.register-btn:hover{background:#1b5e20;}
.links{margin-top:15px;text-align:center;font-size:13px;}
.links a{color:#2e7d32;text-decoration:none;font-weight:500;transition:color 0.3s;}
.links a:hover{color:#1b5e20;text-decoration:underline;}
.footer-text{margin-top:20px;text-align:center;font-size:12px;color:#777;}
.error-box{background:#ffebee;color:#c62828;border:1px solid #ffcdd2;padding:12px;margin-bottom:15px;border-radius:6px;}
.success-box{background:#e8f5e9;color:#2e7d32;border:1px solid #c8e6c9;padding:12px;margin-bottom:15px;border-radius:6px;}

/* Password strength meter */
.strength-meter{margin-top:5px;height:4px;border-radius:2px;background:#eee;overflow:hidden;position:relative;}
.strength-meter::after{content:'';display:block;height:100%;width:0;background:#ff4444;transition:width 0.3s, background 0.3s;position:absolute;top:0;left:0;}

/* Form validation styles */
input.valid{border-color:#4caf50;}
input.invalid{border-color:#f44336;}
.validation-message{font-size:12px;margin-top:3px;display:none;}
.validation-message.valid{color:#4caf50;display:block;}
.validation-message.invalid{color:#f44336;display:block;}

/* Loading state */
.register-btn.loading{opacity:0.7;cursor:not-allowed;position:relative;}
.register-btn.loading::after{content:'';position:absolute;right:15px;top:50%;width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite;}
@keyframes spin{to{transform:translateY(-50%) rotate(360deg);}}

/* Password field wrapper */
.password-wrapper{position:relative;}

/* Password toggle button */
.toggle-password{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:18px;padding:0;width:24px;height:24px;color:#666;display:flex;align-items:center;justify-content:center;transition:color 0.2s;}
.toggle-password:hover{color:#2e7d32;}
.toggle-password:focus{outline:none;color:#1b5e20;}

/* Adjust input padding for toggle button */
.password-wrapper input[type="password"],
.password-wrapper input[type="text"]{padding-right:40px;}
</style>
</head>
<body>
<div class="register-container">
    <div class="logo-box">GEO SOCIETY<br>LOGO</div>
    <h2>Create Account</h2>
    <p class="subtitle">Geo Society Portal – University of Malawi</p>

    <?php if(!empty($errors)): ?>
        <div class="error-box">
            <?php foreach($errors as $error): ?>
                <p><?php echo htmlspecialchars($error); ?></p>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <form method="post" id="registerForm" novalidate>
        <!-- CSRF Token -->
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        
        <div class="form-group">
            <label for="full_name">Full Name *</label>
            <input type="text" name="full_name" id="full_name" 
                   placeholder="e.g. Fortune Kamphinda" 
                   required 
                   value="<?php echo htmlspecialchars($full_name); ?>">
            <div class="hint">Enter your full name as it appears in university records</div>
        </div>

        <div class="form-group">
            <label for="studentId">Student ID *</label>
            <input type="text" name="student_id" id="studentId" 
                   placeholder="e.g. BSC-GEO-19-24" 
                   required 
                   pattern="^(BSC-GEO|BED-GEO|BSC-GLY)-\d{2}-\d{2}$"
                   title="Format: BSC-GEO-YY-YY, BED-GEO-YY-YY, or BSC-GLY-YY-YY"
                   value="<?php echo htmlspecialchars($student_id); ?>">
            <div class="hint">Format: BSC-GEO-YY-YY, BED-GEO-YY-YY, or BSC-GLY-YY-YY</div>
        </div>

        <div class="form-group">
            <label for="email">University Email</label>
            <input type="email" id="email" readonly 
                   value="<?php echo htmlspecialchars($email); ?>">
            <div class="hint">Email is automatically generated from your Student ID</div>
        </div>

        <div class="form-group">
            <label for="year">Year of Study *</label>
            <select name="year" id="year" required>
                <option value="">Select year</option>
                <option value="Year 1" <?php echo ($year=="Year 1") ? "selected" : ""; ?>>Year 1</option>
                <option value="Year 2" <?php echo ($year=="Year 2") ? "selected" : ""; ?>>Year 2</option>
                <option value="Year 3" <?php echo ($year=="Year 3") ? "selected" : ""; ?>>Year 3</option>
                <option value="Year 4" <?php echo ($year=="Year 4") ? "selected" : ""; ?>>Year 4</option>
            </select>
        </div>

        <div class="form-group">
            <label for="password">Password *</label>
            <div class="password-wrapper">
                <input type="password" name="password" id="password" required 
                       minlength="8"
                       pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$">
                <button type="button" class="toggle-password" data-target="password" title="Show password">
                    👁️
                </button>
                <div class="strength-meter" id="strengthMeter"></div>
                <div class="hint">Minimum 8 characters with uppercase, lowercase, and number</div>
                <div class="validation-message" id="passwordMessage"></div>
            </div>
        </div>

        <div class="form-group">
            <label for="confirm_password">Confirm Password *</label>
            <div class="password-wrapper">
                <input type="password" name="confirm_password" id="confirm_password" required>
                <button type="button" class="toggle-password" data-target="confirm_password" title="Show password">
                    👁️
                </button>
                <div class="validation-message" id="confirmMessage"></div>
            </div>
        </div>

        <button class="register-btn" type="submit" id="submitBtn">Create Account</button>
    </form>

    <div class="links">
        Already have an account? <a href="login.php">Login here</a>
    </div>

    <div class="footer-text">
        © <?php echo date('Y'); ?> Geo Society – University of Malawi
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const studentIdInput = document.getElementById("studentId");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirm_password");
    const strengthMeter = document.getElementById("strengthMeter");
    const passwordMessage = document.getElementById("passwordMessage");
    const confirmMessage = document.getElementById("confirmMessage");
    const submitBtn = document.getElementById("submitBtn");
    const form = document.getElementById("registerForm");

    // Password visibility toggle
    document.querySelectorAll('.toggle-password').forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const passwordInput = document.getElementById(targetId);
            const isPassword = passwordInput.type === 'password';
            
            // Toggle input type
            passwordInput.type = isPassword ? 'text' : 'password';
            
            // Update button icon
            if (isPassword) {
                this.innerHTML = '🙈'; // Hide icon
                this.title = 'Hide password';
            } else {
                this.innerHTML = '👁️'; // Show icon
                this.title = 'Show password';
            }
            
            // Keep focus on input for better UX
            passwordInput.focus();
        });
    });

    // Student ID to Email conversion
    studentIdInput.addEventListener("input", function() {
        const id = this.value.toUpperCase().trim();
        this.value = id;
        
        const idPattern = /^(BSC-GEO|BED-GEO|BSC-GLY)-\d{2}-\d{2}$/;
        if (idPattern.test(id)) {
            emailInput.value = `${id}@unima.ac.mw`.toLowerCase();
        } else {
            emailInput.value = "";
        }
    });

    // Password strength checker
    function checkPasswordStrength(password) {
        let strength = 0;
        
        // Length check
        if (password.length >= 8) strength += 25;
        if (password.length >= 12) strength += 10;
        
        // Complexity checks
        if (/[a-z]/.test(password)) strength += 20;
        if (/[A-Z]/.test(password)) strength += 20;
        if (/[0-9]/.test(password)) strength += 20;
        if (/[^A-Za-z0-9]/.test(password)) strength += 5;
        
        return Math.min(strength, 100);
    }

    // Update password strength meter
    passwordInput.addEventListener('input', function() {
        const password = this.value;
        const strength = checkPasswordStrength(password);
        
        // Update meter color and width
        let color = '#ff4444'; // Red
        if (strength >= 60) color = '#ffa700'; // Orange
        if (strength >= 80) color = '#00c851'; // Green
        
        // Update the pseudo-element
        const meterAfter = strengthMeter.querySelector('::after');
        if (meterAfter) {
            meterAfter.style.width = strength + '%';
            meterAfter.style.backgroundColor = color;
        }
        
        // Update CSS custom property
        strengthMeter.style.setProperty('--strength-width', strength + '%');
        strengthMeter.style.setProperty('--strength-color', color);
        
        // Update validation message
        if (password.length === 0) {
            passwordMessage.textContent = '';
            passwordMessage.className = 'validation-message';
        } else if (password.length < 8) {
            passwordMessage.textContent = 'Password too short (min 8 characters)';
            passwordMessage.className = 'validation-message invalid';
        } else if (!/[A-Z]/.test(password)) {
            passwordMessage.textContent = 'Add at least one uppercase letter';
            passwordMessage.className = 'validation-message invalid';
        } else if (!/[a-z]/.test(password)) {
            passwordMessage.textContent = 'Add at least one lowercase letter';
            passwordMessage.className = 'validation-message invalid';
        } else if (!/[0-9]/.test(password)) {
            passwordMessage.textContent = 'Add at least one number';
            passwordMessage.className = 'validation-message invalid';
        } else {
            passwordMessage.textContent = 'Strong password!';
            passwordMessage.className = 'validation-message valid';
        }
        
        // Trigger confirm password check
        if (confirmInput.value) {
            checkPasswordMatch();
        }
    });

    // Check password confirmation
    function checkPasswordMatch() {
        if (passwordInput.value && confirmInput.value) {
            if (passwordInput.value === confirmInput.value) {
                confirmMessage.textContent = 'Passwords match!';
                confirmMessage.className = 'validation-message valid';
                confirmInput.classList.add('valid');
                confirmInput.classList.remove('invalid');
                return true;
            } else {
                confirmMessage.textContent = 'Passwords do not match';
                confirmMessage.className = 'validation-message invalid';
                confirmInput.classList.add('invalid');
                confirmInput.classList.remove('valid');
                return false;
            }
        }
        return null;
    }

    confirmInput.addEventListener('input', checkPasswordMatch);

    // Form submission with validation
    form.addEventListener('submit', function(e) {
        let isValid = true;
        
        // Check password match
        if (!checkPasswordMatch()) {
            isValid = false;
            confirmInput.focus();
        }
        
        // Check password strength
        if (passwordInput.value && checkPasswordStrength(passwordInput.value) < 60) {
            isValid = false;
            passwordInput.focus();
        }
        
        if (!isValid) {
            e.preventDefault();
            alert('Please fix the errors before submitting.');
        } else {
            // Show loading state
            submitBtn.disabled = true;
            submitBtn.classList.add('loading');
            submitBtn.textContent = 'Creating Account...';
        }
    });

    // Real-time validation for Student ID
    studentIdInput.addEventListener('blur', function() {
        const idPattern = /^(BSC-GEO|BED-GEO|BSC-GLY)-\d{2}-\d{2}$/;
        if (this.value && !idPattern.test(this.value)) {
            this.setCustomValidity('Please use format: BSC-GEO-YY-YY, BED-GEO-YY-YY, or BSC-GLY-YY-YY');
            this.reportValidity();
        } else {
            this.setCustomValidity('');
        }
    });
});
</script>
</body>
</html>