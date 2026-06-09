# PHP Multi-Factor Authentication Demo

A demonstration application showcasing three different Multi-Factor Authentication (MFA) approaches using PHP. Built with [Slim Framework](https://www.slimframework.com/) and [Twig](https://twig.symfony.com/), this project is intended as a talk/workshop companion to illustrate how MFA can be integrated into a PHP web app.

## MFA Methods Demonstrated

| Method | Description |
|---|---|
| **Vonage Verify (SMS OTP)** | Sends a one-time passcode via SMS using the [Vonage Verify v2 API](https://developer.vonage.com/en/verify/overview) |
| **TOTP (Time-Based OTP)** | Authenticator app support (e.g. Google Authenticator, Authy) via [RobThree/TwoFactorAuth](https://github.com/RobThree/TwoFactorAuth) |
| **WebAuthn (Passkey)** | Hardware/biometric key authentication via the [madwizard/webauthn](https://github.com/madwizard-thomas/webauthn-server) library |

## Prerequisites

- PHP 8.1+
- [Composer](https://getcomposer.org/)
- A [Vonage](https://developer.vonage.com/) account with:
  - A Vonage Application (with Voice or Verify capability)
  - A Vonage virtual phone number
  - The application's private key file

## Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/Vonage-Community/demo-verify-php-with-mfa.git
   cd demo-verify-php-with-mfa
   ```

2. **Install dependencies**

   ```bash
   composer install
   ```

3. **Configure environment variables**

   Copy or edit the `.env` file with your Vonage credentials:

   ```env
   BRAND="Your App Name"
   VONAGE_APPLICATION_ID="your-vonage-application-id"
   VONAGE_NUMBER="your-vonage-number"
   ```

4. **Add your private key**

   Place your Vonage application's `private.key` file in the project root.

## Running the Application

Start the built-in PHP development server from the `src` directory:

```bash
php -S localhost:8080 -t src
```

Then open [http://localhost:8080](http://localhost:8080) in your browser.

> **Note for WebAuthn:** WebAuthn requires HTTPS and a valid domain. Use a tunneling tool such as [ngrok](https://ngrok.com/) and update the Relying Party origin in `src/WebAuthRouter.php` to match your tunnel URL.

## Application Flow

1. **Register** — Create a session user with a username, password, and phone number.
2. **Log in** — Authenticate with username and password.
3. **Choose MFA method** — From the MFA selection page, pick one of the three methods to verify your identity.
4. **Profile** — Access the protected profile page once fully verified.

## Project Structure

```
src/
├── index.php           # App bootstrap, DI container, and route definitions
├── DefaultRouter.php   # Home page
├── LoginRouter.php     # Login, logout, MFA method selection
├── RegisterRouter.php  # User registration
├── ProfileRouter.php   # Protected profile page
├── VerifyRouter.php    # Vonage Verify v2 (SMS OTP) routes
├── TOTPRouter.php      # TOTP registration & verification routes
├── WebAuthRouter.php   # WebAuthn registration & authentication routes
├── UserService.php     # Session-based user management
├── User.php            # User model
└── WebAuthStorage.php  # WebAuthn credential store

templates/              # Twig HTML templates
```

## Dependencies

- [slim/slim](https://github.com/slimphp/Slim) — Micro-framework for routing
- [slim/twig-view](https://github.com/slimphp/Twig-View) — Twig template integration
- [php-di/php-di](https://php-di.org/) — Dependency injection container
- [vonage/client](https://github.com/Vonage/vonage-php-sdk-core) — Vonage PHP SDK
- [robthree/twofactorauth](https://github.com/RobThree/TwoFactorAuth) — TOTP implementation
- [madwizard/webauthn](https://github.com/madwizard-thomas/webauthn-server) — WebAuthn server
- [endroid/qr-code](https://github.com/endroid/qr-code) + [bacon/bacon-qr-code](https://github.com/Bacon/BaconQrCode) — QR code generation for TOTP setup

## License

This project is provided as a demo/educational resource. See [LICENSE](LICENSE) for details.
