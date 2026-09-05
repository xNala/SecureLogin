<?php
declare(strict_types=1);

namespace Library\IPQS;

use Library\Config\Config;

class Tracker
{
    /**
     * Generates the JS tracker HTML
     *
     * @return string
     */
    public function GenerateTracker(): string {
        $trackerLink = sprintf('https://www.ipqscloud.com/api/%s/%s', Config::IPQS_TRACKER_DOMAIN, Config::IPQS_TRACKER_KEY);
        return "<script src='".sprintf('%s/%s', $trackerLink, 'learn.js')."' crossorigin='anonymous'></script><noscript><img src='".sprintf('%s/%s', $trackerLink, 'pixel.png')."'/></noscript>";
    }
}
