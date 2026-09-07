<?php 
declare(strict_types=1);

require_once __DIR__ . '/Library/autoload.php';

use Library\CSRF\CSRF;
use Library\IPQS\Postback;
use Library\User\DeviceCheck;
use Library\Database\Database;

$csrf = new CSRF();
$db = new Database();
$ipqs = new Postback();
$user = new DeviceCheck();

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

if ($ipqs->IsRequestIDConsumed($input['request_id']) === true) {
    exit(print(json_encode(['success' => false, 'message' => 'failed request_id consumed check', 'csrf_token' => $csrf->GenerateToken()])));
}

if ($ipqs->ConsumeRequestID($input['request_id'], $_SESSION['user']['userID']) === false) {
    exit(print(json_encode(['success' => false, 'message' => 'failed consuming request_id', 'csrf_token' => $csrf->GenerateToken()])));
}

$deviceID = $ipqs->GenerateHighEntropyDeviceID($postbackResult);

if ($input['type'] === 'heartbeat') {
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
