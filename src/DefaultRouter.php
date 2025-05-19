<?php

namespace Vonage\Security;

use DI\Container;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;

class DefaultRouter
{
    private Twig $view;

    public function __construct(Container $container)
    {
        $this->view = $container->get('view');
    }

    public function __invoke(Request $request, Response $response): Response
    {
        return $this->view->render($response, 'index.html.twig');
    }
}