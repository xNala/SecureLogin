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

if ($user->IsMFAComplete() === false) {
    exit(header('Location: /mfa.php'));
}

if ($user->ValidateSession() === false) {
    $user->InvalidateMFA();
    exit(header('Location: /mfa.php'));
}

$csrfToken = htmlspecialchars($csrf->GenerateToken(), ENT_QUOTES, 'UTF-8');
$trackerJS = $tracker->GenerateTracker();

$quotes = [
    'And you may ask yourself.... How did I get here?',
    "He was on my mind long before I ever met him, I'd put down the mic just to feel that way forever.",
    "Didn't get dressed... but, at least I went outside.".PHP_EOL."Didn't go outside... but, at least I got dressed.",
    "Her friends said she's changed... She's always upset...".PHP_EOL.'Versace shades and a Gucci sundress to hide the pain~',
    "They say you had an episode. I don't blame you at all.".PHP_EOL.'And everything thinks less of you. Until they know the result.'
];

$outputText = $quotes[array_rand($quotes)];

?>
<html>
    <head>
        <title>Restricted Page</title>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css' rel='stylesheet'>
        <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js'></script>
    </head>

    <body>
        <nav class='navbar navbar-expand-lg bg-dark' data-bs-theme='dark'>
            <div class='container-fluid'>
                <a class='navbar-brand' href='#'>Logo/Brand</a>
                <button class='navbar-toggler' type='button' data-bs-toggle='collapse' data-bs-target='#navbarContent' aria-controls='navbarContent' aria-expanded='false' aria-label='Toggle navigation'>
                    <span class='navbar-toggler-icon'></span>
                </button>
                <div class='collapse navbar-collapse' id='navbarContent'>
                    <ul class='navbar-nav me-auto mb-2 mb-lg-0'>
                        <li class='nav-item'>
                            <a class='nav-link active' aria-current='page' href='/index.php'>Home</a>
                        </li>
                    </ul>
                    <div class='d-flex'>
                      <a class='btn btn-outline-danger' href='/logout.php'>Logout</a>
                    </div>
                </div>
            </div>
        </nav>
        <main class='d-flex align-items-center justify-content-center min-vh-100 bg-body-tertiary'>
            <div class='card shadow-sm text-center' style='max-width:600px;'>
                <div class='card-body p-4'>
                    <h2 style='white-space: pre-line;'><?php echo $outputText; ?></h2>
                    <br>
                    <h3>This session is device ID locked!</h3>
                    <small>Account Email: <?php echo $user->GetEmail(); ?></small>
                    <br>
                    <br>
                    <button class='btn btn-primary' type='button' onclick='protectedAction()'>
                        Protected Action
                    </button>
                </div>
            </div>
        </main>
            
        <?php echo $trackerJS; ?>

        <script>
            var csrfToken = <?php echo json_encode($csrfToken); ?>;
            var requestID = null;

            // probably dont need this for your usecase - preventing burning a credit on page load
            Startup.Pause();
            
            function validateDeviceID() {
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
                        type: 'heartbeat'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.csrf_token !== undefined && data.csrf_token !== '') {
                        csrfToken = data.csrf_token;
                    }
                  
                    if (data.success === true) {
                        alert('Protected action validated.');
                        return;
                    }
            
                    alert('Protected action failed: ' + data.message);
            
                    if (data.redirect !== undefined && data.redirect !== '') {
                        window.location.href = data.redirect;
                    }
                })
                .catch(error => {
                    alert('Protected action failed: ' + error.message);
                });
            }

            // probably not required for your setup - i just dont want to refresh the page
            function reloadTracker() {
                var oldScript = document.querySelector('script[src*="learn.js"]');
                var oldNoscript = document.querySelector('noscript');
                
                if (oldScript !== undefined && oldScript !== false) {
                    var trackerUrl = oldScript.src;
                    var pixelUrl = trackerUrl.replace('/learn.js', '/pixel.png');
                    
                    oldScript.remove();
                    if (oldNoscript !== undefined && oldNoscript !== false) {
                        oldNoscript.remove();
                    }
                    
                    var script = document.createElement('script');
                    script.src = trackerUrl;
                    script.crossOrigin = 'anonymous';
                    script.onload = function() {
                        var noscript = document.createElement('noscript');
                        var img = document.createElement('img');
                        img.src = pixelUrl;
                        noscript.appendChild(img);
                        document.body.appendChild(noscript);
                        
                        setTimeout(function() {
                            Startup.Pause(); // credit burn prevention - you probably dont need this
                            Startup.AfterResult(function(result) {
                                requestID = result.request_id;
                                validateDeviceID();
                            });
                            Startup.Resume(); // resume the fingerprinter
                        }, 50);
                    };
                    document.body.appendChild(script);
                }
            }
        
            function protectedAction() {
                reloadTracker();
            }
        </script>
    </body>
</html
