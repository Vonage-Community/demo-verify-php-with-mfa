<?php
declare(strict_types=1);

namespace Vonage\Security;

use DI\Container;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;

class RegisterRouter
{
    private Twig $view;

    public function __construct(Container $container)
    {
        $this->view = $container->get('view');
    }

    public function registerUser(Request $request, Response $response): Response
    {
        $query = $request->getQueryParams();
        return $this->view->render(
            $response,
            'register.html.twig',
            [
                'msg'  => array_key_exists('msg', $query) ? $query['msg'] : null,
                'success'  => array_key_exists('success', $query) ? $query['success'] : null,
                'info' => array_key_exists('info', $query) ? $query['info'] : null,
            ]
        );
    }


    public function createUser(Request $request, Response $response): Response
    {
        $requestBody = $request->getParsedBody();
        $user = new User(
            $requestBody['username'],
            $requestBody['password'],
            $requestBody['phone']
        );

        UserService::save($user);

        return $response->withStatus(302)->withHeader('Location', '/login?success=' . urlencode('You have been registered'));
    }

    public function deleteUser(Request $request, Response $response): Response
    {
        UserService::unregister();
        return $response->withStatus(204);
    }
}