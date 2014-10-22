<?php
namespace LinguaLeo\Security\Cookie;

use LinguaLeo\Security\CookieInterface;

class BinaryCookie implements CookieInterface
{
    private $id;
    private $salt;

    public function __construct($id = null, $salt = null)
    {
        $this->id = $id;
        $this->salt = md5($salt);
    }

    /**
     * {@inheritdoc}
     */
    public function getChecksum()
    {
        return $this->id.$this->salt;
    }

    /**
     * {@inheritdoc}
     */
    public function pack($sig)
    {
        return bin2hex(pack('LH32H*', $this->id, $this->salt, $sig));
    }

    /**
     * {@inheritdoc}
     */
    public function unpack($raw)
    {
        $data = @unpack('Lid/H32salt/H*sig', hex2bin($raw));
        $this->id = $data['id'];
        $this->salt = $data['salt'];
        return $data['sig'];
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function isValid()
    {
        return is_int($this->id) && $this->id > 0;
    }

    /**
     * {@inheritdoc}
     */
    public function invalidate()
    {
        $this->id = null;
        return $this;
    }
}
