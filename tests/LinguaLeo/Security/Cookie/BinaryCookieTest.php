<?php

namespace LinguaLeo\Security\Cookie;

class BinaryCookieTest extends \PHPUnit_Framework_TestCase
{
    public function providerPackage()
    {
        return [
            ['01000000e7a8f1d8b045098d76172897a21d6373ac3548cfe2', 'ac3548cfe2', 1, 9636],
            ['0200000084e2d85ac232c681a641da1ec663888c0d6a1d13f1', '0d6a1d13f1', 2, 6117],
            ['0300000045645a27c4f1adc8a7a835976064a86d6a1d13fd9e', '6a1d13fd9e', 3, 626],
            ['0400000054229abfcfa5649e7003b83dd47552945827057a', '5827057a', 4, 91],
        ];
    }

    public function providerNotValidId()
    {
        return [
            [true],
            [array()],
            [new \stdClass()],
            ['ff'],
            ['00a']
        ];
    }

    /**
     * @dataProvider providerPackage
     */
    public function testPack($package, $sig, $id, $salt)
    {
        $this->assertSame($package, (new BinaryCookie($id, $salt))->pack($sig));
    }

    /**
     * @dataProvider providerPackage
     */
    public function testUnpack($package, $sig, $id)
    {
        $cookie = new BinaryCookie();
        $this->assertSame($sig, $cookie->unpack($package));
        $this->assertTrue($cookie->isValid());
        $this->assertSame($id, $cookie->getId());
    }

    /**
     * @dataProvider providerNotValidId
     */
    public function testIsNotValid($id)
    {
        $this->assertFalse((new BinaryCookie($id))->isValid());
    }

}