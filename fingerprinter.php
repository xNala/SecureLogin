<?php 
declare(strict_types=1);

require_once __DIR__ . '/Library/autoload.php';

use Library\CSRF\CSRF;
use Library\IPQS\Tracker;
use Library\User\DeviceCheck;

$csrf = new CSRF();
$user = new DeviceCheck();
$tracker = new Tracker();

if ($user->IsLoggedIn() === false) {
    exit(header('Location: /login.php'));
}

if ($user->IsMFAComplete() === true) {
    exit(header('Location: /index.php'));
}

if ($user->ValidateSession() === false) {
    exit(header('Location: /mfa.php'));
}

$csrfToken = htmlspecialchars($csrf->GenerateToken(), ENT_QUOTES, 'UTF-8');
$trackerJS = $tracker->GenerateTracker();

?>
<html>
    <head>
        <title>Redirecting</title>
        <meta charset='utf-8'>
    </head>

    <body>
        <p>Redirecting...</p>
        
        <?php echo $trackerJS; ?>

        <script>
            const csrfToken = <?php echo json_encode($csrfToken); ?>;

            function submitDeviceID(requestID) {
                fetch('/api.php', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        request_id: requestID,
                        csrf_token: csrfToken,
                        type: 'login'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success === true) {
                        window.location.href = data.redirect;
                        return;
                    }

                    document.body.innerHTML = '<p>Device verification failed. ' + response.message + '</p>';
                })
                .catch(() => {
                    document.body.innerHTML = '<p>Device verification failed. ' + response.message + '</p>';
                });
            }
            
            var IPQ = {
                Callback: function() {
                    Startup.AfterResult(function(result) {
                        if (!result || typeof result.device_id !== 'string' || result.device_id.length === 0) {
                            document.body.innerHTML = '<p>Device verification failed. ' + result.message + ' </p>';
                            return;
                        }

                        submitDeviceID(result.request_id);
                    });

                    Startup.Init();
                }
            };
        </script>
        
    </body>
</html>
