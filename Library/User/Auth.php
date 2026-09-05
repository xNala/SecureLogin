<?php
declare(strict_types=1);

namespace Library\User;

use PDO;
use Library\User\CurrentUser;
use Library\Database\Database;

class Auth extends CurrentUser {
    private Database $DB;
    
    /**
     * Auth Constructor
     */
    function __construct() {
        parent::__construct();

        $this->DB = new Database();
    }

    /**
     * Login verification
     *
     * @param string $email - account email
     * @param string $password - account password
     * @return bool 
     */
    public function DoLogin(string $email, string $password): bool {
        $users = $this->DB->DoQuery('SELECT `id`, `email`, `password` FROM `users` WHERE `email` = :email', ['email' => $email]);
        if ($users === null || $users->rowCount() === 0) {
            return false;
        }

        $user = $users->fetch(PDO::FETCH_ASSOC);
        if (password_verify($password, $user['password']) === true) {
            $this->SetUser(intval($user['id']));
            return true;
        }
        
        return false;
    }

    /**
     * Placeholder MFA verification - if the code is 000000 it will return true
     * Will not be implenenting proper rfc6238 MFA in this example
     * 
     * @param string $input - MFA input code
     * @return bool
     */ 
    public function VerifyMFA(string $input): bool {
        if ($input === '000000') {
            return true;
        }
        
        return false;
    }

    /**
     * Sets MFA to not complete
     *
     * @return void
     */
    public function InvalidateMFA(): void {
        $_SESSION['user']['mfaComplete'] = false;
    }
}
