<?php

namespace Vonage\Security;

use Vonage\Client\Exception\Exception;

class InvalidLoginException extends Exception
{
    protected $message = 'Invalid Username or Password.';
}