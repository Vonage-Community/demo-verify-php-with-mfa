<?php

namespace Vonage\Security;

use DI\Container;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Views\Twig;
use Vonage\Verify2\Request\SMSRequest;
use Vonage\Client;

class VerifyRouter
{
    private Twig $view;

    private Client $client;

    public function __construct(Container $container)
    {
        $this->view = $container->get('view');
        $this->client = $container->get(Client::class);
    }

    public function verifyPage(Request $request, Response $response, array $args): Response
    {
        if (UserService::isLoggedIn()) {
            $response
                ->withStatus(302)
                ->withHeader('Location', '/login?msg=' . urlencode('You need to be logged in to access 2222'));
        }

        return $this->view->render($response, 'verify.html.twig');
    }

    public function startVerify(Request $request, Response $response, array $args): Response
    {
        if (!UserService::isLoggedIn()) {
            $response
                ->getBody()
                ->write(json_encode(['error' => 'Not logged in']));

            return $response
                ->withStatus(400)
                ->withHeader('Content-Type', 'application/json');
        }

        $statusCode = 200;
        try {
            $user = UserService::getUser();

            $phone = sprintf("+1%s", $user->phone);
            $smsRequest = new SMSRequest(
                $phone,
                'PHPTek'
            );

            $smsRequest->setTimeout(15);
            $result = $this->client->verify2()->startVerification($smsRequest);

            $response
                ->getBody()
                ->write(json_encode($result));
        } catch (\Exception $e) {
            $statusCode = 500;
            $response
                ->getBody()
                ->write(json_encode(['error' => $e->getMessage()]));
        }

        return $response
            ->withStatus($statusCode)
            ->withHeader('Content-Type', 'application/json');
    }

    public function verifyCode(Request $request, Response $response, array $args): Response
    {
        if (!UserService::isLoggedIn()) {
            $response
                ->getBody()
                ->write(json_encode(['error' => 'Not logged in']));

            return $response
                ->withStatus(400)
                ->withHeader('Content-Type', 'application/json');
        }

        $requestBody = json_decode($request->getBody()->getContents());
        try {
            UserService::verifyUser(function () use ($requestBody) {
                $this->client->verify2()->check($requestBody->requestId, $requestBody->code);
                return true;
            });
            return $response->withStatus(200);
        } catch (\Exception $e) {
            $response
                ->getBody()
                ->write(json_encode(['error' => $e->getMessage()]));
            return $response->withStatus(400);
        }
    }
}