<?php
namespace LinguaLeo\Security\Cookie;

use LinguaLeo\Security\CookieInterface;

class BinaryCookie implements CookieInterface
{
    private $uniq;
    private $salt;

    public function __construct($uniq = null, $salt = null)
    {
        $this->uniq = $uniq;
        $this->salt = md5($salt);
    }

    /**
     * {@inheritdoc}
     */
    public function getChecksum()
    {
        return $this->uniq.$this->salt;
    }

    /**
     * {@inheritdoc}
     */
    public function pack($sig)
    {
        return bin2hex(pack('LH32H*', $this->uniq, $this->salt, $sig));
    }

    /**
     * {@inheritdoc}
     */
    public function unpack($raw)
    {
        $data = @unpack('Luniq/H32salt/H*sig', hex2bin($raw));
        $this->uniq = $data['uniq'];
        $this->salt = $data['salt'];
        return $data['sig'];
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->uniq;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid()
    {
        return is_int($this->uniq) && $this->uniq > 0;
    }

    /**
     * {@inheritdoc}
     */
    public function invalidate()
    {
        $this->uniq = null;
    }
}
