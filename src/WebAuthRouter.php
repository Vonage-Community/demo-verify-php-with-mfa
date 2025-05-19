<?php

namespace Vonage\Security;

use DI\Container;
use MadWizard\WebAuthn\Builder\ServerBuilder;
use MadWizard\WebAuthn\Config\RelyingParty;
use MadWizard\WebAuthn\Credential\UserCredential;
use MadWizard\WebAuthn\Credential\UserHandle;
use MadWizard\WebAuthn\Exception\VerificationException;
use MadWizard\WebAuthn\Json\JsonConverter;
use MadWizard\WebAuthn\Server\Authentication\AuthenticationOptions;
use MadWizard\WebAuthn\Server\Registration\RegistrationOptions;
use MadWizard\WebAuthn\Server\ServerInterface;
use MadWizard\WebAuthn\Server\UserIdentity;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;

class WebAuthRouter
{
    private Twig $view;

    private static ServerInterface $_server;


    public function __construct(Container $container)
    {
        $this->view = $container->get('view');
    }

    public static function getWebAuthnServer(): ServerInterface
    {
        if (isset(WebAuthRouter::$_server))
        {
            return WebAuthRouter::$_server;
        }

        $rp = new RelyingParty('Manchuck', 'https://manchuck.ngrok.io');
        $store = new \Vonage\Security\WebAuthStorage();
        $builder = new ServerBuilder();

        return WebAuthRouter::$_server = $builder
            ->setRelyingParty($rp)
            ->setCredentialStore($store)
            ->build();
    }

    public function registerPage(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn()) {
            return $response->withStatus(302)->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in to access the profile page'));
        }

        if (!UserService::isVerified()) {
            return $response->withStatus(302)->withHeader('Location', '/mfa?msg=' . urlencode('Your login has not been verified'));
        }

        $user = UserService::getUser();

        return $this->view->render($response, 'register-webauth.html.twig', [
            'user' => json_decode($user->serialize(), true),
        ]);
    }

    public function webAuthPage(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn()) {
            return $response->withStatus(302)->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in to access the profile page'));
        }

        $user = UserService::getUser();
        $query = $request->getQueryParams();
        return $this->view->render($response, 'verify-webauth.html.twig', [
            'msg'  => array_key_exists('msg', $query) ? $query['msg'] : null,
            'success'  => array_key_exists('success', $query) ? $query['success'] : null,
            'info' => array_key_exists('info', $query) ? $query['info'] : null,
            'user' => json_decode($user->serialize(), true),
        ]);
    }
    public function startRegistration(Request $request, Response $response): Response
    {
        $loggedInUser = UserService::getUser();
        $user = new UserIdentity(
            UserHandle::fromString($loggedInUser->username),
            $loggedInUser->username,
            $loggedInUser->username
        );

        $options = RegistrationOptions::createForUser($user);
        $server = self::getWebAuthnServer();
        $registration = $server->startRegistration($options);

        UserService::storeRegistrationContext($registration->getContext());

        $response
            ->getBody()
            ->write(json_encode(JsonConverter::encodeDictionary($registration->getClientOptions())));

        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');
    }

    public function completeRegistration(Request $request, Response $response): Response
    {
        try {
            $context = UserService::getRegistrationContext();
            $server = self::getWebAuthnServer();
            $requestBody = json_decode($request->getBody()->getContents(), true);
            $result = $server->finishRegistration(JsonConverter::decodeAttestation($requestBody), $context);
            $credentialedUser = new UserCredential(
                $result->getCredentialId(),
                $result->getPublicKey(),
                $result->getUserHandle(),
            );
            UserService::saveUserCredential($credentialedUser);
        } catch (\Exception $e) {
            return $response->withStatus(200);
        }

        return $response->withStatus(200);
    }

    public function startAuthentication(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn())
        {
            throw new InvalidLoginException();
        }

        $credentialedUser = UserService::getUserCredential();
        if ($credentialedUser === null)
        {
            throw new InvalidLoginException();
        }

        $options = AuthenticationOptions::createForUser($credentialedUser->getUserHandle());
        $server = self::getWebAuthnServer();
        $auth = $server->startAuthentication($options);

        UserService::storeAuthenticationContext($auth->getContext());

        $response
            ->getBody()
            ->write(json_encode(JsonConverter::encodeDictionary($auth->getClientOptions())));

        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');
    }

    public function completeAuthentication(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn())
        {
            throw new InvalidLoginException();
        }

        $responseCode = 200;
        $server = self::getWebAuthnServer();
        try {
            UserService::verifyUser(function () use (&$request, &$server) {
                $server->finishAuthentication(
                    JsonConverter::decodeAssertionString($request->getBody()),
                    UserService::getAuthenticationContext(),
                );
                return true;
            });

            $response
                ->getBody()
                ->write(json_encode([
                    'msg' => 'Key verified'
                ]));
        } catch (InvalidLoginException $login) {
            return $response->withStatus(302)->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in'));
        } catch (VerificationException $verificationException) {
            $response
                ->getBody()
                ->write(json_encode([
                    'error' => $verificationException->getMessage(),
                ]));

            $responseCode = 401;
        } catch (\Exception $exception) {
            $response
                ->getBody()
                ->write(json_encode([
                    'error' => $exception->getMessage(),
                ]));

            $responseCode = 500;
        }

        return $response->withStatus($responseCode);
    }
}