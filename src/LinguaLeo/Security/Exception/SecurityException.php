<?php
namespace LinguaLeo\Security\Exception;

// @codeCoverageIgnoreStart
class SecurityException extends \Exception
{
    const NO_DATA = 0;
    const INVALID_DATA = 1;
    const SIGNATURE_VIOLATION = 2;
}
// @codeCoverageIgnoreEnd
