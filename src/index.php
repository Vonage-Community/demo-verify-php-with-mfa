<?php
declare(strict_types=1);

use DI\Container;
use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;
use Slim\Factory\AppFactory;
use Slim\Views\Twig;
use Slim\Views\TwigMiddleware;
use Vonage\Client;
use Vonage\Client\Credentials\Keypair;
use Vonage\Security\WebAuthRouter;
use Vonage\Security\RegisterRouter;
use Vonage\Security\DefaultRouter;
use Vonage\Security\ProfileRouter;
use Vonage\Security\LoginRouter;
use Vonage\Security\VerifyRouter;
use Vonage\Security\TOTPRouter;

error_reporting(E_ALL & ~E_DEPRECATED);

session_start();

require __DIR__ . '/../vendor/autoload.php';

// Instantiate App
$container = new Container();
AppFactory::setContainer($container);

$app = AppFactory::create();
$app->addErrorMiddleware(true, true, true);

//Create Vonage client
$client = new Client(
    new Keypair(
        file_get_contents(__DIR__ . '/../private.key'),
        'b787e68f-bcca-4944-a976-7d6c362974e6'
    )
);
$container->set(Client::class, $client);

// Create TOTP client
$tfa = new TwoFactorAuth(new BaconQrCodeProvider());
$container->set(TwoFactorAuth::class, $tfa);

// Create Twig
$twig = Twig::create(__DIR__ . '/../templates');
$container->set('view', $twig);
$app->add(TwigMiddleware::create($app, $twig));

// Home Page
$app->get('/', DefaultRouter::class);

// User Registration
$app->get('/register', [RegisterRouter::class, 'registerUser']);
$app->post('/register', [RegisterRouter::class, 'createUser']);
$app->delete('/register', [RegisterRouter::class, 'deleteUser']);

// Profile Page
$app->get('/profile', ProfileRouter::class);

// Login routes
$app->get('/login', [LoginRouter::class, 'loginPage']);
$app->post('/login', [LoginRouter::class, 'login']);
$app->get('/mfa', [LoginRouter::class, 'mfaPage']);
$app->get('/logout', [LoginRouter::class, 'logout']);

// Vonage Verify
$app->get('/verify', [VerifyRouter::class, 'verifyPage']);
$app->post('/start-verify', [VerifyRouter::class, 'startVerify']);
$app->post('/verify-code', [VerifyRouter::class, 'verifyCode']);

// TOTP
$app->get('/register-totp', [TOTPRouter::class, 'registerTOTP']);
$app->post('/verify-totp', [TOTPRouter::class, 'verifyTOTP']);
$app->get('/totp', [TOTPRouter::class, 'TOTPPage']);

// web-auth
$app->get('/register-web-auth', [WebAuthRouter::class, 'registerPage']);
$app->get('/web-auth', [WebAuthRouter::class, 'webAuthPage']);
$app->get('/web-auth-register', [WebAuthRouter::class, 'startRegistration']);
$app->post('/web-auth-register', [WebAuthRouter::class, 'completeRegistration']);
$app->get('/auth-web-auth', [WebAuthRouter::class, 'startAuthentication']);
$app->post('/auth-web-auth', [WebAuthRouter::class, 'completeAuthentication']);
$app->run();