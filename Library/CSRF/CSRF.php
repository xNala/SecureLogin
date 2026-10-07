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

        $tokens = $this->GetTokens();
        $tokens[$hash] = time() + self::TOKEN_LIFETIME;
        $_SESSION['csrf_tokens'] = $tokens;
        
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

        $tokens = $this->GetTokens();
        $hash = hash('sha256', $token);
        
        if (isset($tokens[$hash]) === false) {
            return false;
        }

        $expires = $tokens[$hash];

        // token is valid, consume it
        unset($tokens[$hash]);
        $_SESSION['csrf_tokens'] = $tokens;
        
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

        $tokens = $this->GetTokens();
        $now = time();

        foreach ($tokens as $hash => $expires) {
            if ($expires < $now) {
                unset($tokens[$hash]);
            }
        }

        $_SESSION['csrf_tokens'] = $tokens;
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

        $tokens = $this->GetTokens();
        
        if (count($tokens) <= self::MAX_TOKENS) {
            return;
        }

        asort($tokens);

        while (count($tokens) > self::MAX_TOKENS) {
            array_shift($tokens);
        }

        $_SESSION['csrf_tokens'] = $tokens;
    }

    /**
     * Get the CSRF tokens from the session as a typed array
     *
     * @return array<string, int>
     */
    private function GetTokens(): array {
        $stored = $_SESSION['csrf_tokens'] ?? [];

        if (is_array($stored) === false) {
            return [];
        }

        $tokens = [];

        foreach ($stored as $hash => $expires) {
            if (is_string($hash) === true && is_int($expires) === true) {
                $tokens[$hash] = $expires;
            }
        }
        
        return $tokens;
    }
}