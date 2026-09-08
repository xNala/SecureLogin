<?php
declare(strict_types=1);

namespace Library\IPQS;

use Library\Config\Config;
use Library\Database\Database;

class Postback
{
    /**
     * Queries the IPQS Postback API with the request ID to check this session
     *
     * note: you should probably prevent requestID re-use
     *
     * @param string $requestID
     * @return array
     */
    public function ResultsPostback(string $requestID): array {  
        $url = sprintf(
            'https://www.ipqualityscore.com/api/json/postback/%s?request_id=%s',
            Config::IPQS_API_KEY,
            rawurlencode($requestID)
        );
    
        $curl = curl_init($url);
    
        curl_setopt_array($curl, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => Config::DEBUGMODE,
            CURLOPT_SSL_VERIFYHOST => Config::DEBUGMODE,
        ]);
    
        $response = curl_exec($curl);
        curl_close($curl);
        
        if ($response === false) {
            return [];
        }
    
        $result = json_decode($response, true);
        
        if (
            is_array($result) === false ||
            ($result['success'] ?? false) !== true
        ) {
           return [];
        }
        
        return $result;
    }

    /**
     * Takes a VALID response from the IPQS Postback API to then generate a high entropy device identifier
     *
     * @param array $postbackResult
     * @return string
     */
    public function GenerateHighEntropyDeviceID(array $postbackResult): string {
        // using an identifier that uses multiple of the user's fingerprint values is going to be more secure
        // this could be considered an "HWID" tied to that browser instance on that computer
        $deviceID = hash(
            'sha256',
            sprintf(
                '%s-%s-%s-%s-%s', 
                $postbackResult['device_id']       ?? '', // should be unique to the device itself
                $postbackResult['canvas_hash']     ?? '', // changes for GPU, Driver (and version), and Browser combinations
                $postbackResult['webgl_hash']      ?? '',
                $postbackResult['graphics_card']   ?? '', // the name of the device's graphics processor
                $postbackResult['ssl_fingerprint'] ?? ''  // hash of te browser's supported SSL/TLS ciphers
            )
        );
        
        return $deviceID;
    }

    /**
     * Checks if a given request ID is already marked as consumed in the database
     *
     * @param string $requestID
     * @return bool
     */
    public function IsRequestIDConsumed(string $requestID): bool {
        $db = new Database();
        
        // check if the request ID is already consumed
        $requestIDs = $db->DoQuery('SELECT `request_id` from `consumed_request_ids` WHERE `request_id` = :rid', ['rid' => $requestID]);
        if ($requestIDs === null) {
            return true;
        }
        
        if ($requestIDs->rowCount() > 0) {
            return true;
        }

        return false;
    }
    
    /**
     * Consumes a request ID
     *
     * @param string $requestID
     * @return bool
     */
    public function ConsumeRequestID(string $requestID, int $userID): bool {
        $db = new Database();
        
        // mark this requestID as used - to prevent replay attacks
        $stmt = $db->DoQuery('INSERT INTO `consumed_request_ids` (`user_id`, `request_id`) VALUES (?, ?)', [$userID, $requestID]);
        
        if ($stmt === null) {
            return false;
        }   

        return true;
    }
}
