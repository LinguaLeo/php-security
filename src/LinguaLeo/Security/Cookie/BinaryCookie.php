<?php

namespace LinguaLeo\Security\Cookie;

use LinguaLeo\Security\CookieInterface;

class BinaryCookie implements CookieInterface
{
    private $id;
    private $ts;
    private $salt;

    public function __construct($id = null, $ts = null, $salt = null)
    {
        $this->id = $id;
        $this->ts = $ts;
        $this->salt = $salt;
    }

    public function getChecksum()
    {
        return $this->id.'/'.$this->ts.'/'.$this->salt;
    }

    public function pack($sig)
    {
        return bin2hex(pack('SLLH*', $this->salt, $this->id, $this->ts, $sig));
    }

    public function unpack($raw)
    {
        $data = unpack('Ssalt/Lid/Lts/H*sig', hex2bin($raw));
        $this->id = $data['id'];
        $this->ts = $data['ts'];
        $this->salt = $data['salt'];
        return $data['sig'];
    }

    public function isAlive($threshold)
    {
        return $this->ts >= $threshold;
    }

    public function getId()
    {
        return $this->id;
    }

    public function isValid()
    {
        return $this->isPositive($this->id, $this->ts, $this->salt);
    }

    private function isPositive()
    {
        foreach (func_get_args() as $v) {
            if (!(is_int($v) && $v > 0)) {
                return false;
            }
        }
        return true;
    }

    public function invalidate()
    {
        $this->id = null;
        $this->ts = null;
        $this->salt = null;
    }
}