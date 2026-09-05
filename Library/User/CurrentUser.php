<?php
declare(strict_types=1);

namespace Library\User;

use PDO;
use Library\Database\Database;

class CurrentUser {
    private Database $DB;
    
    /**
     * User Constructor, sets up the cookie... starts the session
     */
    function __construct() {
        $this->DB = new Database();
        
        if (session_status() === PHP_SESSION_NONE) {
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'secure' => (isset($_SERVER['HTTPS']) === true),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            
            session_start();
        } 

        if (isset($_SESSION['user']) === false) {
            $_SESSION['user'] = [];
        }

        if (isset($_SESSION['csrf_tokens']) === false) {
            $_SESSION['csrf_tokens'] = [];
        }
    }

    /**
     * Returns the current user's email
     *
     * @return string
     */
    public function GetEmail(): string {
        if (isset($_SESSION['user']['userID']) === false) {
            return '';
        }

        $users = $this->DB->DoQuery(
            'SELECT `email` FROM `users` WHERE `id` = :uid',
            [
                'uid' => $_SESSION['user']['userID']
            ]
        );

        if ($users === null || $users->rowCount() === 0) {
            return '';
        }

        $user = $users->fetch(PDO::FETCH_ASSOC);

        return $user['email'];
    }
    
    /**
     * Determines if the current user is logged in
     *
     * @return bool
     */
    public function IsLoggedIn(): bool {
        if (isset($_SESSION['user']['loggedIn']) === true && $_SESSION['user']['loggedIn'] === true) {
            return true;
        }

        return false;
    }

    /**
     * Determines if the current user has completed MFA
     *
     * @return bool
     */
    public function IsMFAComplete(): bool {
        if (isset($_SESSION['user']['mfaComplete']) === true && $_SESSION['user']['mfaComplete'] === true) {
            return true;
        }
        
        return false;
    }

    /**
     * Insert a new session entry into the database
     *
     * @param string $sessionID
     * @return bool
     */
    public function InsertSession(string $sessionID): bool {
        $stmt = $this->DB->DoQuery('INSERT INTO `user_sessions` (`session_id`, `user_id`) VALUES (?, ?)', [$sessionID, $_SESSION['user']['userID']]);

        if ($stmt === null) {
            return false;
        }
        
        return true;
    }

    /**
     * Marks the user's current session (in DB) as revoked
     *
     * @return bool
     */
    public function RevokeSession(): bool {
        if (isset($_SESSION['user']['userID']) === false) {
            return false;
        }

        $this->DB->DoQuery(
            'UPDATE `user_sessions` SET `revoked_at` = CURRENT_TIMESTAMP WHERE `session_id` = :sid AND `user_id` = :uid AND `revoked_at` IS NULL',
            [
                'sid' => session_id(),
                'uid' => $_SESSION['user']['userID']
            ]
        );

        return true;
    } 
    
    /**
     * Validates the session exists in the DB for the current user, and is not revoked
     *
     * @return bool
     */
    public function ValidateSession(): bool {
        if (isset($_SESSION['user']['userID']) === false) {
            return false;
        }

        $sessionID = session_id();

        $sessions = $this->DB->DoQuery(
            'SELECT `id`, `session_id`, `user_id`, `device_id`, `created_at`, `last_seen_at`, `revoked_at` FROM `user_sessions` WHERE `session_id` = :sid AND `user_id` = :uid',
            [
                'sid' => $sessionID, 
                'uid' => $_SESSION['user']['userID']
            ]
        );
        
        if ($sessions === null || $sessions->rowCount() === 0) {
            return false;
        }

        $session = $sessions->fetch(PDO::FETCH_ASSOC);
        if ($session['revoked_at'] !== null) {
            return false;
        }

        return true;
    }
    
    /**
     * Sets the session values to log in as the provided userID
     *
     * @param int $userID
     * @return void
     */
    protected function SetUser(int $userID): void {
        $_SESSION['user'] = [
            'loggedIn' => true,
            'userID' => $userID,
            'mfaComplete' => false,
        ];
    }
}
