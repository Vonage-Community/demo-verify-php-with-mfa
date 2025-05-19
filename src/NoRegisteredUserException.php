<?php

namespace Vonage\Security;

use Vonage\Client\Exception\Exception;

class NoRegisteredUserException extends Exception
{
    protected $message = 'No registered user found.';
}