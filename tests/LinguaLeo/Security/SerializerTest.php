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

        $this->serializer = new Serializer(new HMAC(), 'verysecretlongkey');
    }

    public function providerPackage()
    {
        return [
            [
                '01000000797b14534f37b2fc34dd07fe11deaa57c84084e1764567902ac8e19f85893185a7e0a75a',
                1,
                1393851257
            ]
        ];
    }

    /**
     * @dataProvider providerPackage
     */
    public function testSerialize($package, $id, $now)
    {
        $cookie = new BinaryCookie($id, $now);
        $this->assertSame($package, $this->serializer->serialize($cookie));
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
    public function testUnserialize($package, $id, $now)
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