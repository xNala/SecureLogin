<?php
declare(strict_types=1);

require_once __DIR__ . '/Library/autoload.php';

use Library\CSRF\CSRF;
use Library\User\Auth;

$user = new Auth();
$csrf = new CSRF();

if ($user->IsLoggedIn() === false) {
    exit(header('Location: /login.php'));
}

if ($user->IsMFAComplete() === true) {
    exit(header('Location: /index.php'));
}

if (isset($_POST['submit-mfa']) === true) {
    if (
        isset($_POST['mfa-code']) === true &&
        isset($_POST['csrf-token']) === true
    ) {
        if ($csrf->VerifyToken($_POST['csrf-token']) === false) {
            exit('Invalid CSRF token');
        }
        
        if ($user->VerifyMFA($_POST['mfa-code']) === true) {
            // regenerate the sessionId and store it in the database
            session_regenerate_id(true);
            $sessionId = session_id();

            if ($user->InsertSession($sessionId) === true) {
                exit(header('Location: /fingerprinter.php'));
            }
        }
    }
}

$csrfToken = htmlspecialchars($csrf->GenerateToken(), ENT_QUOTES, 'UTF-8');
?>

<html>
    <head>
        <title>MFA Page</title>
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
                    <h1 class='fs-4 fw-semibold mt-2 mb-3'>Secure MFA</h1>
                    
                    <form method='post'>
                        <div class='mb-2'>
                            <label for='mfa-code' class='form-label visually-hidden'>MFA Token</label>
                            <input type='text' name='mfa-code' class='form-control form-control-lg text-center' id='mfa-code' placeholder='hardcoded to 000000' autocomplete='off' required>
                        </div>

                        <input type='hidden' name='csrf-token' value='<?php echo $csrfToken ?>' \>
                        <button class='btn btn-primary w-100' type='submit' name='submit-mfa'><i class='bi bi-magic me-2'></i>Enter</button>
                    </form>
                </div>
            </div>
        </main>
    </body>
</html>
