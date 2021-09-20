<?php


namespace camilord\phpclamav\VirusScanner;


use camilord\utilus\Data\ArrayUtilus;
use camilord\utilus\IO\FileUtilus;

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
     * apt install clamav
     *
     * @param string $file - full path of the file
     * @param int $scan_mode
     * @return null|ScanResult
     */
    public function scan($file, $scan_mode = 1)
    {
        if (!file_exists($file) || !is_file($file)) {
            return null;
        }
        if (!$this->command_exists('clamscan')) {
            return null;
        }

        $scan_mode = intval($scan_mode);
        $cmd = "clamscan [MODES] \"{$file}\"";
        $modes = "";

        if ($scan_mode === self::AV_SCAN_MODE_FULL) {
            $modes .= " --detect-pua=yes ";
            $modes .= " --detect-structured=yes ";
            $modes .= " --phishing-sigs=yes ";
            $modes .= " --algorithmic-detection=yes ";
        } else if ($scan_mode === self::AV_SCAN_MODE_PHISHING) {
            $modes .= " --phishing-sigs=yes ";
        } else if ($scan_mode === self::AV_SCAN_MODE_STRUCTURED) {
            $modes .= " --detect-structured=yes ";
        } else if ($scan_mode === self::AV_SCAN_MODE_PUA) {
            $modes .= " --detect-pua=yes ";
        } else if ($scan_mode === self::AV_SCAN_MODE_ALGORITHMIC) {
            $modes .= " --algorithmic-detection=yes ";
        } else {
            $modes = "";
        }

        if (strtolower(FileUtilus::get_extension($file)) === 'pdf') {
            $modes .= " --scan-pdf=yes ";
        }

        $cmd = str_replace("[MODES]", $modes, $cmd);

        ob_start();
        system($cmd);
        $cli_output = ob_get_contents();
        ob_end_clean();

        return $this->process_result($file, $cli_output);
    }

    /**
     * apt install clamav-daemon
     *
     *

        /home/camilord/Downloads/Invoice 553941367 10.31.2017.doc: Doc.Dropper.Agent-6360876-0 FOUND

        ----------- SCAN SUMMARY -----------
        Infected files: 1
        Time: 0.089 sec (0 m 0 s)

     *
     * @param string $file - full path of the file
     * @return ScanResult|null
     */
    public function daemon_scan($file)
    {
        if (!file_exists($file) || !is_file($file)) {
            return null;
        }
        if (!$this->command_exists('clamdscan')) {
            return null;
        }

        $cmd = "clamdscan \"{$file}\"";

        ob_start();
        system($cmd);
        $cli_output = ob_get_contents();
        ob_end_clean();

        return $this->process_result($file, $cli_output);
    }

    /**
     * @param string $file
     * @param mixed $cli_output
     * @return ScanResult
     */
    private function process_result(string $file, $cli_output)
    {
        $result = new ScanResult();

        $tmp = explode('----------- SCAN SUMMARY -----------', $cli_output);

        $stats = [];
        $summary_notes = '';
        if (isset($tmp[1])) {
            $summary_notes = trim($tmp[1]);
            $stats = $this->process_stats($summary_notes);
        }

        $result_tmp = $this->process_stats($cli_output);

        $key = str_replace(' ', '', ucwords(trim($file)));
        $virus_name = $result_tmp[$key];

        if (preg_match("/FOUND/", $virus_name)) {
            $virus_name = trim(str_replace('FOUND', '', $virus_name));
            $result->setIsVirus(true);
            $result->setVirusName($virus_name);
        } else {
            $result->setIsVirus(false);
        }
        unset($result_tmp);

        $result->setSummaryNotes($summary_notes);
        $result->setStats($stats);

        return $result;
    }

    /**
     * @param string $command_name
     * @return bool
     */
    private function command_exists($command_name)
    {
        return (null === shell_exec("command -v {$command_name}")) ? false : true;
    }

    /**
     * @param $stats_text
     * @return array
     */
    private function process_stats($stats_text)
    {
        $array_stats = [];
        $lines = explode("\n", $stats_text);
        foreach($lines as $line) {
            if (stripos($line, ':') !== false) {
                $tmp = explode(':', $line);
                $key = str_replace(' ', '', ucwords(trim($tmp[0])));

                if (count($tmp) > 2) {
                    array_shift($tmp);
                    $array_stats[$key] = trim(implode(':', $tmp));
                } else {
                    $val = trim($tmp[1]);
                    $array_stats[$key] = $val;
                }
            }
        }

        return $array_stats;
    }
}