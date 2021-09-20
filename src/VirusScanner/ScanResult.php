<?php


namespace camilord\phpclamav\VirusScanner;

/**
 * Class ScanResult
 * @package camilord\phpclamav\VirusScanner
 */
class ScanResult
{
    private $isVirus = false;
    private $virusName = '';
    private $summaryNotes = '';
    private $stats = [];

    /**
     * @return bool
     */
    public function isVirus()
    {
        return $this->isVirus;
    }

    /**
     * @param bool $isVirus
     */
    public function setIsVirus($isVirus)
    {
        $this->isVirus = $isVirus;
    }

    /**
     * @return string
     */
    public function getVirusName()
    {
        return $this->virusName;
    }

    /**
     * @param string $virusName
     */
    public function setVirusName($virusName)
    {
        $this->virusName = $virusName;
    }

    /**
     * @return string
     */
    public function getSummaryNotes()
    {
        return $this->summaryNotes;
    }

    /**
     * @param string $summaryNotes
     */
    public function setSummaryNotes($summaryNotes)
    {
        $this->summaryNotes = $summaryNotes;
    }

    /**
     * @return array
     */
    public function getStats(): array
    {
        return $this->stats;
    }

    /**
     * @param array $stats
     */
    public function setStats(array $stats): void
    {
        $this->stats = $stats;
    }

}