<?php

namespace Vonage\Security;

use DI\Container;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;

class LoginRouter
{
    private Twig $view;

    public function __construct(Container $container)
    {
        $this->view = $container->get('view');
    }

    public function loginPage(Request $request, Response $response): Response
    {
        $query = $request->getQueryParams();
        return $this->view->render($response, 'login.html.twig', [
            'msg'  => array_key_exists('msg', $query) ? $query['msg'] : null,
            'success'  => array_key_exists('success', $query) ? $query['success'] : null,
            'info' => array_key_exists('info', $query) ? $query['info'] : null,
        ]);
    }

    public function logout(Request $request, Response $response, array $args): Response
    {
        UserService::logout();
        return $response
            ->withStatus(302)
            ->withHeader('Location', '/login?info=' . urlencode('You have been logged out'));
    }

    public function mfaPage(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn()) {
            return $response
                ->withStatus(302)
                ->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in to access'));
        }

        $query = $request->getQueryParams();
        $view = Twig::fromRequest($request);
        return $view->render($response, 'mfa.html.twig', [
            'msg'  => array_key_exists('msg', $query) ? $query['msg'] : null,
            'success'  => array_key_exists('success', $query) ? $query['success'] : null,
            'info' => array_key_exists('info', $query) ? $query['info'] : null,
        ]);
    }

    public function login(Request $request, Response $response): Response
    {
        $requestBody = $request->getParsedBody();
        $username = $requestBody['username'];
        $password = $requestBody['password'];

        try {
            UserService::login($username, $password);
            return $response->withStatus(302)->withHeader('Location', '/mfa');
        } catch (NoRegisteredUserException $noRegisteredUserException) {
            return $response
                ->withStatus(302)
                ->withHeader('Location', '/register?msg=' . urlencode($noRegisteredUserException->getMessage()));
        } catch (InvalidLoginException $invalidLoginException) {
            return $response
                ->withStatus(302)
                ->withHeader('Location', '/login?msg=' . urlencode($invalidLoginException->getMessage()));
        }
    }
}