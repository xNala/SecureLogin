<?php
declare(strict_types=1);

require_once __DIR__ . '/Library/autoload.php';

use Library\User\DeviceCheck;

$user = new DeviceCheck();

if ($user->IsLoggedIn() === false) {
    exit(header('Location: /login.php'));
}

session_start();

$user->RevokeSession();

$_SESSION = [];

if (ini_get('session.use_cookies') !== false) {
    $params = session_get_cookie_params();

    setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}

session_destroy();

exit(header('Location: /login.php'));
