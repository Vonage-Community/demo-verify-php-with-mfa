<?php
/**
 * PHP built-in server router for single-port operation.
 *
 * Lets PHP serve both the built Reveal.js presentation and the Slim API on
 * the same port so the whole demo can be tunnelled through a single ngrok URL.
 *
 * Usage (from project root, after building the presentation):
 *
 *   npm --prefix presentation run build
 *   php -S 0.0.0.0:8080 -t presentation/dist router.php
 *
 * How it works:
 *   1. Static files that exist inside presentation/dist are returned as-is
 *      (PHP's built-in server handles them natively when the router returns false).
 *   2. Requests whose path starts with /api/ have the prefix stripped so that
 *      /api/register → /register, matching the Slim route definitions.
 *   3. Every other request is handed to the Slim application in src/index.php.
 */

declare(strict_types=1);

$requestUri  = $_SERVER['REQUEST_URI'];
$requestPath = parse_url($requestUri, PHP_URL_PATH);

// 1. Serve static files from the built presentation directory directly.
$staticFile = __DIR__ . '/presentation/dist' . $requestPath;
if (is_file($staticFile)) {
    return false; // let PHP's built-in server send the file with the correct MIME type
}

// 2. Strip the /api prefix so that presentation fetch calls (/api/register, etc.)
//    map to Slim routes (/register, etc.).
if (str_starts_with($requestPath, '/api/')) {
    $_SERVER['REQUEST_URI'] = substr($requestUri, strlen('/api'));
}

// 3. Bootstrap the Slim application.
require __DIR__ . '/src/index.php';
