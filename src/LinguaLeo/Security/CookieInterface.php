<?php
namespace LinguaLeo\Security;

interface CookieInterface
{
    /**
     * Returns a checksum string
     *
     * @return string
     */
    public function getChecksum();

    /**
     * Packs a cookie by signature
     *
     * @param string $sig
     * @return string
     */
    public function pack($sig);

    /**
     * Unpacks a cookie and returns a signature string
     *
     * @param string $raw
     * @return string
     */
    public function unpack($raw);

    /**
     * Returns an identifier
     *
     * @return mixed
     */
    public function getId();

    /**
     * Checks cookie's data
     *
     * @return bool
     */
    public function isValid();

    /**
     * Invalidates cookie's data
     *
     * @return CookieInterface
     */
    public function invalidate();
}
