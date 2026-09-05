<?php
declare(strict_types=1);

namespace Library\User;

use PDO;
use Library\User\Auth;
use Library\Database\Database;

class DeviceCheck extends Auth {
    private Database $DB;
    
    /**
     * Device check constructor
     */
    function __construct() {
        parent::__construct();

        $this->DB = new Database();
    }

    /**
     * Validates if the user's session's device ID matches the provided input
     *
     * @param string $deviceID
     * @return bool
     */
    public function ValidateDeviceID(string $deviceID): bool {
        if (isset($_SESSION['user']['userID']) === false) {
            return false;
        }

        $sessions = $this->DB->DoQuery(
            'SELECT `device_id` FROM `user_sessions` WHERE `session_id` = :sid AND `user_id` = :uid AND `revoked_at` IS NULL',
            [
                'sid' => session_id(),
                'uid' => $_SESSION['user']['userID']
            ]
        );

        if ($sessions === null || $sessions->rowCount() !== 1) {
            return false;
        }
    
        $session = $sessions->fetch(PDO::FETCH_ASSOC);

        if ($session['device_id'] === null) {
            return false;
        }

        if ($session['device_id'] !== $deviceID) {
            $this->DB->DoQuery(
                'UPDATE `user_sessions` SET `revoked_at` = CURRENT_TIMESTAMP WHERE `session_id` = :sid AND `user_id` = :uid AND `revoked_at` IS NULL',
                [
                    'sid' => session_id(),
                    'uid' => $_SESSION['user']['userID']
                ]
            );
    
            return false;
        }
    
        return true;
    }
    
    /**
     * Assigns a device ID to the session
     *
     * @param string $deviceID
     * @return bool
     */
    public function SetDeviceID(string $deviceID): bool {
        if (isset($_SESSION['user']['userID']) === false) {
            return false;
        }
        
        $stmt = $this->DB->DoQuery(
            'UPDATE `user_sessions` SET `device_id` = :device_id WHERE `session_id` = :sid AND `user_id` = :uid AND `revoked_at` IS NULL',
            [
                'device_id' => $deviceID,
                'sid' => session_id(),
                'uid' => $_SESSION['user']['userID']
            ]
        );

        if ($stmt === null || $stmt->rowCount() !== 1) {
            return false;
        }

        $_SESSION['user']['mfaComplete'] = true;
    
        return true;
    }
}
