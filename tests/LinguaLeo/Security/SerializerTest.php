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
            ['01000000dc912a253d1e9ba40e2c597ed2376640f9228fdff3ae916fd236150f2427c6d3cac687a6', 1, 385],
            ['020000007a614fd06c325499f1680b9896beedeb7fe3d81ea85291fff4b58e4f53675b5c62be88da', 2, 272],
            ['0300000098dce83da57b0395e163467c9dae521b2fd59665be642ffe38366e361c9ffa5154351bbc', 3, 93],
        ];
    }

    /**
     * @dataProvider providerPackage
     */
    public function testSerialize($package, $id, $salt)
    {
        $this->assertSame($package, $this->serializer->serialize(new BinaryCookie($id, $salt)));
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
    public function testUnserialize($package, $id)
    {
        $cookie = $this->serializer->unserialize(new BinaryCookie(), $package);
        $this->assertTrue($cookie->isValid());
        $this->assertSame($id, $cookie->getId());
    }

    public function testFailedUnserialize()
    {
        $cookie = $this->serializer->unserialize(new BinaryCookie(), '01000000'.md5(time()));
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
