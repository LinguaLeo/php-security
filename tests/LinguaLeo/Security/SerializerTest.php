<?php
namespace LinguaLeo\Security;

use LinguaLeo\Security\Signature\HMAC;
use LinguaLeo\Security\Cookie\BinaryCookie;
use LinguaLeo\Security\Exception\SecurityException;

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
     * @expectedException \LinguaLeo\Security\Exception\ValidationException
     * @expectedExceptionMessage The cookie has an invalid data.
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

    /**
     * @expectedException \LinguaLeo\Security\Exception\SignatureDoesNotMatchException
     * @expectedExceptionMessage The signature verification is not passed.
     */
    public function testFailedUnserialize()
    {
        $this->serializer->unserialize(new BinaryCookie(), '01000000'.md5(time()));
    }

    /**
     * @expectedException \LinguaLeo\Security\Exception\ValidationException
     * @expectedExceptionMessage The cookie "abcd" has an invalid format.
     */
    public function testFailedValidationOnUnserialize()
    {
        $this->serializer->unserialize(new BinaryCookie(), 'abcd');
    }

    /**
     * @expectedException \LinguaLeo\Security\Exception\ValidationException
     * @expectedExceptionMessage The cookie is empty.
     */
    public function testFailedUnserializeForEmptyCookie()
    {
        $this->serializer->unserialize(new BinaryCookie(), '');
    }

    public function provideWrongCookieFormats()
    {
        return [
            [''],
            ['abcd'],
            ['01000000'.md5(time())]
        ];
    }

    /**
     * @dataProvider provideWrongCookieFormats
     */
    public function testInvalidationWithCatchException($raw)
    {
        $cookie = new BinaryCookie(75772);
        try {
            $this->serializer->unserialize($cookie, $raw);
        } catch (SecurityException $e) {
            $this->assertFalse($cookie->isValid());
            error_log($e->getMessage());
        }
    }
}
