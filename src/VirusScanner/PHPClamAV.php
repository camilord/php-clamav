<?php


namespace camilord\phpclamav\VirusScanner;


/**
 * Class PHPClamAV
 * @package camilord\phpclamav\VirusScanner
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
        if (!file_exists($file) || !is_file($file)) {
            return null;
        }

        $scan_mode = intval($scan_mode);
        $cmd = "clamscan [MODES] \"{$file}\"";
        $modes = "";

        if ($scan_mode === self::AV_SCAN_MODE_FULL) {
            $modes .= " --detect-pua=y ";
            $modes .= " --detect-structured=y ";
            $modes .= " --phishing-sigs=y ";
            $modes .= " --algorithmic-detection=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_PHISHING) {
            $modes .= " --phishing-sigs=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_STRUCTURED) {
            $modes .= " --detect-structured=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_PUA) {
            $modes .= " --detect-pua=y ";
        } else if ($scan_mode === self::AV_SCAN_MODE_ALGORITHMIC) {
            $modes .= " ---algorithmic-detection=y ";
        } else {
            $modes = "";
        }
        $cmd = str_replace("[MODES]", $modes, $cmd);

        ob_start();
        system($cmd);
        $cli_output = ob_get_contents();
        ob_end_clean();

        $result = new ScanResult();

        $tmp = explode('----------- SCAN SUMMARY -----------', $cli_output);
        if (preg_match("/FOUND/", $tmp[0])) {
            $virus_name = trim(str_replace($file.':', '', trim($tmp[0])));
            $virus_name = trim(str_replace('FOUND', '', $virus_name));
            $result->setIsVirus(true);
            $result->setVirusName($virus_name);
        } else {
            $result->setIsVirus(false);
        }
        $result->setSummaryNotes(trim(@$tmp[1]));

        return $result;
    }
}