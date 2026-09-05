<?php 
declare(strict_types=1);

require_once __DIR__ . '/Library/autoload.php';

use Library\CSRF\CSRF;
use Library\IPQS\Postback;
use Library\User\DeviceCheck;
use Library\Database\Database;

$user = new DeviceCheck();
$csrf = new CSRF();
$ipqs = new Postback();
$db   = new Database();

header('Content-Type: application/json');

if ($user->IsLoggedIn() === false) {
    exit(print(json_encode(['success' => false, 'redirect' => '/login.php']))); 
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    exit(print(json_encode(['success' => false])));
}

$input = json_decode(file_get_contents('php://input'), true);

if (
    is_array($input) === false ||
    isset($input['csrf_token']) === false
) {
    exit(print(json_encode(['success' => false, 'message' => 'missing required csrf token'])));
}

if ($csrf->VerifyToken($input['csrf_token']) === false) {
    exit(print(json_encode(['success' => false, 'message' => 'invalid csrf token'])));
}

if (
    isset($input['request_id']) === false ||
    isset($input['type']) === false
) {
    exit(print(json_encode(['success' => false, 'message' => 'missing required input', 'csrf_token' => $csrf->GenerateToken()])));
}

if (
    is_string($input['request_id']) === false ||
    $input['request_id'] === ''
) {
    exit(print(json_encode(['success' => false, 'message' => 'invalid request_id input', 'csrf_token' => $csrf->GenerateToken()])));
}

$postbackResult = $ipqs->ResultsPostback($input['request_id']);

if (
    $postbackResult === [] || 
    $postbackResult['success'] === false
) {
    exit(print(json_encode(['success' => false, 'message' => 'ipqs postback failed', 'csrf_token' => $csrf->GenerateToken()])));
}

// check if the request ID is already consumed
$requestIDs = $db->DoQuery('SELECT `request_id` from `consumed_request_ids` WHERE `request_id` = :rid', ['rid' => $input['request_id']]);
if ($requestIDs === null) {
    exit(print(json_encode(['success' => false, 'message' => 'failed fetching previous request_ids', 'csrf_token' => $csrf->GenerateToken()])));
}

if ($requestIDs->rowCount() > 0) {
    exit(print(json_encode(['success' => false, 'message' => 'request_id already consumed', 'csrf_token' => $csrf->GenerateToken()])));
}

// mark this requestID as used - to prevent replay attacks
$stmt = $db->DoQuery('INSERT INTO `consumed_request_ids` (`user_id`, `request_id`) VALUES (?, ?)', [$_SESSION['user']['userID'], $input['request_id']]);

if ($stmt === null) {
    exit(print(json_encode(['success' => false, 'message' => 'unexpected error consuming request_id', 'csrf_token' => $csrf->GenerateToken()])));
}   


// using an identifier that uses multiple of the user's fingerprint values is going to be more secure
// this could be considered an "HWID" tied to that browser instance on that computer
$deviceID = sha1(
    sprintf(
        '%s-%s-%s-%s-%s', 
        $postbackResult['device_id'],       // should be unique to the device itself
        $postbackResult['canvas_hash'],     // changes for GPU, Driver (and version), and Browser combinations
        $postbackResult['webgl_hash'],
        $postbackResult['graphics_card'],   // the name of the device's graphics processor
        $postbackResult['ssl_fingerprint']  // hash of te browser's supported SSL/TLS ciphers
    )
);

if ($input['type'] === 'login') {    
    if ($user->IsMFAComplete() === true) {
        exit(print(json_encode(['success' => false, 'redirect' => '/index.php', 'message' => 'MFA already complete']))); 
    }
    
    if ($user->ValidateSession() === false) {
        exit(print(json_encode(['success' => false, 'redirect' => '/mfa.php', 'message' => 'invalid session']))); 
    }
    
    if ($user->SetDeviceID($deviceID) === false) {
        exit(print(json_encode(['success' => false, 'message' => 'failed to set device id for this session'])));
    }

    exit(print(json_encode(['success' => true, 'redirect' => '/index.php']))); 
} elseif ($input['type'] === 'heartbeat') {
    if ($user->IsMFAComplete() === false) {
        exit(print(json_encode(['success' => false, 'redirect' => '/mfa.php', 'message' => 'mfa not complete']))); 
    }
    
    if ($user->ValidateSession() === false) {
        $user->InvalidateMFA();
        exit(print(json_encode(['success' => false, 'redirect' => '/mfa.php', 'message' => 'invalid session']))); 
    }
    
    if ($user->ValidateDeviceID($deviceID) === false) {
        $user->InvalidateMFA();
        exit(print(json_encode(['success' => false, 'redirect' => '/mfa.php', 'message' => 'session hijacking detected'])));
    }

    exit(print(json_encode(['success' => true, 'csrf_token' => $csrf->GenerateToken()]))); 
} else {
    exit(print(json_encode(['success' => false, 'message' => 'invalid type', 'csrf_token' => $csrf->GenerateToken()])));
}
