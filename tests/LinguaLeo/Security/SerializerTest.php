<?php

namespace LinguaLeo\Security;

use LinguaLeo\Security\Signature\HMAC;
use LinguaLeo\Security\Cookie\BinaryCookie;

class SerializerTest extends \PHPUnit_Framework_TestCase
{
    private $serializer;

    public function setUp()
    {
        parent::setUp();

        $this->serializer = new Serializer(new HMAC('sha1'), 'verysecretlongkey');
    }

    public function providerPackage()
    {
        return [
            ['683b01000000797b1453b5a60f007e138bf2c3e8b122f1d3fb6ee847e29b', 1, 1393851257, 15208],
            ['942e02000000887b14531e66808a01ec40b745b4280ea43d202f18d6e8b2', 2, 1393851272, 11924],
            ['3a00030000009d7b1453f4ce282d191307023f4cbc4b23a22fb71cb30b2c', 3, 1393851293, 58],
        ];
    }

    /**
     * @dataProvider providerPackage
     */
    public function testSerialize($package, $id, $now, $salt)
    {
        $this->assertSame($package, $this->serializer->serialize(new BinaryCookie($id, $now, $salt)));
    }

    /**
     * @expectedException \LinguaLeo\Security\Exception\SecurityException
     * @expectedExceptionMessage We cannot perform the signature because the cookie is invalid.
     */
    public function testFailedValidationOnSerialize()
    {
        $this->serializer->serialize(new BinaryCookie());
    }

    /**
     * @dataProvider providerPackage
     */
    public function testUnserialize($package, $id, $now, $salt)
    {
        $cookie = $this->serializer->unserialize(new BinaryCookie(), $package);
        $this->assertTrue($cookie->isValid());
        $this->assertSame($id, $cookie->getId());
        $this->assertTrue($cookie->isAlive($now));
    }

    public function testFailedUnserialize()
    {
        $cookie = $this->serializer->unserialize(new BinaryCookie(), md5(time()));
        $this->assertFalse($cookie->isValid());
        $this->assertNull($cookie->getId());
    }

    /**
     * @expectedException \LinguaLeo\Security\Exception\SecurityException
     * @expectedExceptionMessage We cannot perform the verification because the cookie "abcd" is invalid.
     */
    public function testFailedValidationOnUnserialize()
    {
        $this->serializer->unserialize(new BinaryCookie(), 'abcd');
    }
}