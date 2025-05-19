<?php

namespace Vonage\Security;

use DI\Container;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;
use RobThree\Auth\TwoFactorAuth;
use Vonage\Security\UserService;

class TOTPRouter
{
    private Twig $view;

    private TwoFactorAuth $tfa;

    public function __construct(Container $container)
    {
        $this->view = $container->get('view');
        $this->tfa = $container->get(TwoFactorAuth::class);
    }

    public function registerTOTP(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn()) {
            return $response->withStatus(302)->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in to access the profile page'));
        }

        if (!UserService::isVerified()) {
            return $response->withStatus(302)->withHeader('Location', '/mfa?msg=' . urlencode('Your login has not been verified'));
        }

        $user = UserService::getUser();

        $secret = $user->secret;
        if (!isset($secret)) {
            $user->setSecret($this->tfa->createSecret());
            UserService::save($user);
        }

        $qrImage = $this->tfa->getQRCodeImageAsDataUri($user->username, $user->secret);
        return $this->view->render($response, 'register-totp.html.twig', [
            'user' => json_decode($user->serialize(), true),
            'img' => $qrImage,
        ]);
    }

    public function TOTPPage(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn()) {
            return $response->withStatus(302)->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in to access the profile page'));
        }

        $user = UserService::getUser();
        $query = $request->getQueryParams();
        return $this->view->render($response, 'verify-totp.html.twig', [
            'msg'  => array_key_exists('msg', $query) ? $query['msg'] : null,
            'success'  => array_key_exists('success', $query) ? $query['success'] : null,
            'info' => array_key_exists('info', $query) ? $query['info'] : null,
            'user' => json_decode($user->serialize(), true),
        ]);
    }

    public function verifyTOTP(Request $request, Response $response, array $args): Response
    {
        if (!UserService::isLoggedIn()) {
            $response
                ->getBody()
                ->write(json_encode(['msg' => 'User is not logged in']));
            return $response->withStatus(401);
        }

        $user = UserService::getUser();
        $userSecret = $user->secret;
        if (!isset($userSecret)) {
            $response
                ->getBody()
                ->write(json_encode(['msg' => 'No TOTP Registered']));
            return $response->withStatus(400);
        }

        $requestBody = json_decode($request->getBody()->getContents());

        try {
            UserService::verifyUser(function () use ($userSecret, $requestBody) {
                $this->tfa->verifyCode($userSecret, $requestBody->code);
                return true;
            });
            $response
                ->getBody()
                ->write(json_encode(['msg' => 'Code verified']));
            return $response->withStatus(200);
        } catch (\Exception $e) {
            $response
                ->getBody()
                ->write(json_encode(['error' => $e->getMessage()]));
            return $response->withStatus(400);
        }
    }
}