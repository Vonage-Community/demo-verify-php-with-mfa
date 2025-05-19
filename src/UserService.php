<?php

namespace Vonage\Security;

use MadWizard\WebAuthn\Credential\UserCredentialInterface;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationContext;
use MadWizard\WebAuthn\Server\Registration\RegistrationContext;
use Vonage\Client\Exception\Exception;

class UserService
{
    public static function save(User $user): void
    {
        $_SESSION['user'] = serialize($user);
    }

    public static function getUser(): User
    {
        if (!array_key_exists('user', $_SESSION)) {
            throw new NoRegisteredUserException();
        }

        return unserialize($_SESSION['user']);
    }

    public static function login($username, $password): true
    {
        $user = self::getUser();
        if ($username !== $user->username) {
            throw new InvalidLoginException();
        }

        if (password_verify($password, $user->password)) {
           $_SESSION['loggedIn'] = true;
           $_SESSION['verified'] = false;
           return true;
        }

        throw new InvalidLoginException();
    }

    public static function logout(): void
    {
        $_SESSION['loggedIn'] = false;
        $_SESSION['verified'] = false;
    }

    public static function unregister(): void
    {
        $_SESSION['loggedIn'] = false;
        $_SESSION['verified'] = false;
        unset($_SESSION['user']);
    }

    public static function isLoggedIn(): bool
    {
        return $_SESSION['loggedIn'] ?? false;
    }

    public static function isVerified(): bool
    {
        return $_SESSION['verified'] ?? false;
    }

    public static function verifyUser(Callable $callable): bool
    {
        try {
            $_SESSION['verified'] = $callable();
            return $_SESSION['verified'];
        } catch (Exception $e) {
            $_SESSION['verified'] = false;
            throw $e;
        }
    }

    public static function storeAuthenticationContext(AuthenticationContext $ctx): void
    {
        if (!self::isLoggedIn())
        {
            throw new InvalidLoginException();
        }

        $_SESSION['authorization'] = serialize($ctx);
    }

    public static function getAuthenticationContext(): AuthenticationContext
    {
        if (!self::isLoggedIn())
        {
            throw new InvalidLoginException();
        }

        return unserialize($_SESSION['authorization']);
    }

    public static function storeRegistrationContext(RegistrationContext $ctx): void
    {
        if (!self::isLoggedIn())
        {
            throw new InvalidLoginException();
        }

        $_SESSION['registration'] = serialize($ctx);
    }

    public static function getRegistrationContext(): RegistrationContext
    {
        if (!self::isLoggedIn())
        {
            throw new InvalidLoginException();
        }

        return unserialize($_SESSION['registration']);
    }

    public static function saveUserCredential(UserCredentialInterface $credential): void
    {
        if (!self::isLoggedIn())
        {
            throw new InvalidLoginException();
        }

        $_SESSION['credentialed_user'] = serialize($credential);
    }

    public static function getUserCredential(): ?UserCredentialInterface
    {
        if (!self::isLoggedIn())
        {
            return null;
        }

        if (!isset($_SESSION['credentialed_user'])) {
            return null;
        }

        return unserialize($_SESSION['credentialed_user']);
    }
}
