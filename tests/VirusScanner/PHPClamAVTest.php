<?php


namespace camilord\phpclamav\VirusScanner;

use camilord\utilus\IO\SystemUtilus;
use PHPUnit\Framework\TestCase;

/**
 * Class PHPClamAVTest
 * @package camilord\phpclamav\VirusScanner
 */
class PHPClamAVTest extends TestCase
{

    /**
     * @param $filepath
     * @param $expected
     * @param $is_virus
     * @dataProvider getTestFiles
     */
    public function testScanFile($filepath, $expected, $is_virus) {

        if (SystemUtilus::isWin32()) {
            $this->markTestSkipped('for Linux Only');
        }

        $obj = new PHPClamAV();

        echo "\n".(is_file($filepath) ? 'Scanning' : 'Skipping').": {$filepath}\n";
        $result = $obj->scan($filepath);
        $actual = is_object($result);
        $this->assertEquals($actual, $expected);

        if ($result instanceof ScanResult) {
            $this->assertEquals($is_virus, $result->isVirus(), $result->getVirusName());
        }
    }

    /**
     * @param $filepath
     * @param $expected
     * @param $is_virus
     * @dataProvider getTestFiles
     */
    public function testScanFileUsingDaemon($filepath, $expected, $is_virus)
    {
        if (SystemUtilus::isWin32()) {
            $this->markTestSkipped('for Linux Only');
        }

        $obj = new PHPClamAV();

        echo "\n".(is_file($filepath) ? 'Scanning' : 'Skipping').": {$filepath}\n";
        $result = $obj->daemon_scan($filepath);

        $actual = is_object($result);
        $this->assertEquals($actual, $expected);

        if ($result instanceof ScanResult) {
            $this->assertEquals($is_virus, $result->isVirus(), $result->getVirusName());
        }
    }

    /**
     * @return array
     */
    public function getTestFiles() {
        $dir = __DIR__.'/sample_files/';
        $files = scandir($dir);

        $test_files = [];

        foreach($files as $file) {

            $filepath = $dir.$file;

            // if true means able to scan, if false means null result on the scanner
            $expected = (file_exists($filepath) && is_file($filepath)) ? true : false;
            $is_virus = (preg_match("/Invoice.*\\.(doc|zip)$/", $file)) ? true : false;

            $test_files[] = [
                'filepath' => $filepath,
                'expected' => $expected,
                'is_virus' => $is_virus
            ];
        }

        return $test_files;
    }
}