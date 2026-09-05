<?php
declare(strict_types=1);

require_once __DIR__ . '/Library/autoload.php';

use Library\CSRF\CSRF;
use Library\User\Auth;

$user = new Auth();
$csrf = new CSRF();

if ($user->IsLoggedIn() === true) {
    exit(header('Location: /index.php'));
}

if (isset($_POST['login']) === true) {
    if (
        isset($_POST['email']) === true && 
        isset($_POST['password']) === true &&
        isset($_POST['csrf-token']) === true
    ) {
        if ($csrf->VerifyToken($_POST['csrf-token']) === false) {
            exit('Invalid CSRF token');
        }
        
        if ($user->DoLogin($_POST['email'], $_POST['password']) === true) {
            exit(header('Location: /index.php'));
        }
    }
}

$csrfToken = htmlspecialchars($csrf->GenerateToken(), ENT_QUOTES, 'UTF-8');
?>

<html>
    <head>
        <title>Login Page</title>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css' rel='stylesheet'>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js'></script>

        <style>
            .login-card {
                width: 400px;
            }
        </style>
    </head>

    <body>
        <main class='d-flex align-items-center justify-content-center min-vh-100 bg-body-tertiary'>
            <div class='card shadow-sm text-center login-card'>
                <div class='card-body p-4'>
                    <i class='bi bi-envelope-paper fs-1 text-primary'></i>
                    <h1 class='fs-4 fw-semibold mt-2 mb-3'>Secure Sign In</h1>
                    
                    <form method='post'>
                        <div class='mb-2'>
                            <label for='login-email' class='form-label visually-hidden'>Email</label>
                            <input type='email' name='email' class='form-control form-control-lg text-center' id='login-email' placeholder='you@example.com' autocomplete='off' required>
                        </div>

                        <div class='mb-2'>
                            <label for='login-password' class='form-label visually-hidden'>Passowrd</label>
                            <input type='password' name='password' class='form-control form-control-lg text-center' id='login-password' placeholder='*********' autocomplete='username' required>
                        </div>

                        <input type='hidden' name='csrf-token' value='<?php echo $csrfToken ?>' \>
                        <button class='btn btn-primary w-100' type='submit' name='login'><i class='bi bi-magic me-2'></i>Log In</button>
                    </form>
                    <p class='small text-body-secondary mt-3 mb-0'>Dont have an account? <a href='#' class='text-decoration-none'>Register with us!</a></p>
                </div>
            </div>
        </main>
    </body>
</html>
