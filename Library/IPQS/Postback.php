<?php
declare(strict_types=1);

namespace Library\IPQS;

use Library\Config\Config;

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
    function ResultsPostback(string $requestID): array {  
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
            CURLOPT_SSL_VERIFYPEER => false, // <-- this should be TRUE on prod - disabled for my testing environent (Windows hates me)
            CURLOPT_SSL_VERIFYHOST => false, // <-- this should be TRUE on prod - disabled for my testing environent (Windows hates me)
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
}
