<?php


namespace camilord\VirusScanner;


/**
 * Class PHPClamAV
 * @package camilord\VirusScanner
 */
class PHPClamAV
{
    const AV_SCAN_MODE_SIMPLE = 1;
    const AV_SCAN_MODE_PHISHING = 2;
    const AV_SCAN_MODE_STRUCTURED = 3;
    const AV_SCAN_MODE_PUA = 4;
    const AV_SCAN_MODE_ALGORITHMIC = 5;
    const AV_SCAN_MODE_FULL = 10;


    /**
     * @param $file
     * @param int $scan_mode
     * @return null|ScanResult
     */
    public function scan($file, $scan_mode = 1)
    {
        if (!file_exists($file)) {
            return null;
        }

        $scan_mode = intval($scan_mode);
        $cmd = "clamscan [MODES] {$file}";

        if ($scan_mode === self::AV_SCAN_MODE_FULL) {
            $cmd .= " --detect-pua=y ";
            $cmd .= " --detect-structured=y ";
            $cmd .= " --phishing-sigs=y ";
            $cmd .= " --algorithmic-detection=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_PHISHING) {
            $cmd .= " --phishing-sigs=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_STRUCTURED) {
            $cmd .= " --detect-structured=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_PUA) {
            $cmd .= " --detect-pua=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_ALGORITHMIC) {
            $cmd .= " ---algorithmic-detection=y ";
        } else {
            // do nothing ...
        }

        ob_start();
        system($cmd);
        $result = ob_get_contents();
        ob_end_clean();

        $result = new ScanResult();

        return $result;
    }
}