<?php

namespace Vonage\Security;

use DI\Container;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;

class ProfileRouter
{
    private Twig $view;

    public function __construct(Container $container)
    {
        $this->view = $container->get('view');
    }

    public function __invoke(Request $request, Response $response): Response
    {
        if (!UserService::isLoggedIn()) {
            return $response->withStatus(302)->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in to access the profile page'));
        }

        if (!UserService::isVerified()) {
            return $response->withStatus(302)->withHeader('Location', '/mfa?msg=' . urlencode('Your login has not been verified'));
        }

        $user = UserService::getUser()->serialize();

        $query = $request->getQueryParams();
        return $this->view->render($response, 'profile.html.twig', [
            'user' => json_decode($user, true),
            'msg'  => array_key_exists('msg', $query) ? $query['msg'] : null,
            'success'  => array_key_exists('success', $query) ? $query['success'] : null,
            'info' => array_key_exists('info', $query) ? $query['info'] : null,
            'test' => 'test 123',
        ]);
    }
}