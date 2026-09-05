<?php
declare(strict_types=1);

namespace Library\CSRF;

class CSRF {
    private const TOKEN_LIFETIME = 1800;
    private const MAX_TOKENS = 10;

    /**
     * Generate and store a new CSRF token
     *
     * @return string - the CSRF token
     */
    public function GenerateToken(): string {
        $this->Cleanup();
        
        $token = bin2hex(random_bytes(32));
        $hash = hash('sha256', $token);
        
        $_SESSION['csrf_tokens'][$hash] = time() + static::TOKEN_LIFETIME;

        $this->LimitTokens();
        
        return $token;
    }

    /**
     * Verify the input token
     *
     * @param string $token
     * @return bool
     */
    public function VerifyToken(string $token): bool {
        $this->Cleanup();
        
        if (isset($_SESSION['csrf_tokens']) === false) {
            return false;
        }

        $hash = hash('sha256', $token);
        
        if (isset($_SESSION['csrf_tokens'][$hash]) === false) {
            return false;
        }

        $expires = $_SESSION['csrf_tokens'][$hash];

        // token is valid, consume it
        unset($_SESSION['csrf_tokens'][$hash]);
        
        return true;
    }

    /**
     * Remove expired CSRF tokens from the session
     *
     * @return void
     */
    private function Cleanup(): void {
        if (isset($_SESSION['csrf_tokens']) === false) {
            return;
        }

        $now = time();

        foreach ($_SESSION['csrf_tokens'] as $hash => $expires) {
            if ($expires < $now) {
                unset($_SESSION['csrf_tokens'][$hash]);
            }
        }
    }

    /**
     * Prevent unlimited tokens from building up in the session
     *
     * @return void
     */
    private function LimitTokens(): void {
        if (isset($_SESSION['csrf_tokens']) === false) {
            return;
        }
        
        if (count($_SESSION['csrf_tokens']) <= static::MAX_TOKENS) {
            return;
        }

        asort($_SESSION['csrf_tokens']);

        while (count($_SESSION['csrf_tokens']) > static::MAX_TOKENS) {
            array_shift($_SESSION['csrf_tokens']);
        }
    }
}