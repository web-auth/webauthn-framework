<?php

declare(strict_types=1);

/**
 * Front controller for `php -S`. Routes the `/api/*` endpoints; for every
 * other request returns false so the built-in server falls back to serving
 * the matching static file from `public/`. Bare `/` is rewritten to
 * `/index.html` because the built-in server does not auto-index.
 *
 * Run with: php -S localhost:8000 -t public router.php
 */

use App\PasskeyUpgradeDemo\Container;
use ParagonIE\ConstantTime\Base64;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

require_once __DIR__ . '/../src/bootstrap.php';

session_start();
$container = new Container();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($path === '/') {
    $_SERVER['REQUEST_URI'] = '/index.html';

    return false;
}

if (! str_starts_with($path, '/api/')) {
    return false;
}

header('Content-Type: application/json');

try {
    match ($path) {
        '/api/me' => me($container),
        '/api/logout' => logout(),
        '/api/signup' => signup($container),
        '/api/login/password' => loginPassword($container),
        '/api/login/passkey/options' => loginPasskeyOptions($container),
        '/api/login/passkey/verify' => loginPasskeyVerify($container),
        '/api/account/passkey/add/options' => addPasskeyOptions($container),
        '/api/account/passkey/add/verify' => addPasskeyVerify($container),
        '/api/account/passkey/rename' => renamePasskey($container),
        '/api/account/passkey/delete' => deletePasskey($container),
        default => notFound(),
    };
} catch (\Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'error' => $e->getMessage(),
        'class' => $e::class,
    ], \JSON_THROW_ON_ERROR);
}

function notFound(): void
{
    http_response_code(404);
    echo json_encode([
        'error' => 'Not found',
    ], \JSON_THROW_ON_ERROR);
}

/**
 * @return array<string, mixed>
 */
function readJson(): array
{
    $body = file_get_contents('php://input') ?: '{}';
    $json = json_decode($body, true, flags: \JSON_THROW_ON_ERROR);

    return is_array($json) ? $json : [];
}

function jsonOut(mixed $payload): void
{
    echo json_encode($payload, \JSON_THROW_ON_ERROR);
}

function serializeOptions(Container $container, object $options): string
{
    return $container->serializer->serialize($options, 'json', [
        'json_encode_options' => \JSON_THROW_ON_ERROR,
        \Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
    ]);
}

function requireLogin(): string
{
    $userHandleB64 = $_SESSION['userHandle'] ?? null;
    if (! is_string($userHandleB64) || $userHandleB64 === '') {
        http_response_code(401);
        echo json_encode([
            'error' => 'Not authenticated',
        ], \JSON_THROW_ON_ERROR);
        exit;
    }

    return (string) base64_decode($userHandleB64, true);
}

function me(Container $container): void
{
    $userHandleB64 = $_SESSION['userHandle'] ?? null;
    if (! is_string($userHandleB64) || $userHandleB64 === '') {
        http_response_code(401);
        jsonOut([
            'authenticated' => false,
        ]);

        return;
    }
    $userHandle = (string) base64_decode($userHandleB64, true);
    $username = $container->userStore->findUsernameByHandle($userHandle);
    jsonOut([
        'authenticated' => true,
        'authMethod' => $_SESSION['authMethod'] ?? null,
        'username' => $username,
        'displayName' => $username === null ? null : $container->userStore->findDisplayName($username),
        'credentials' => $container->credentialStore->listForUser($userHandle),
    ]);
}

function logout(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42_000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    session_destroy();
    jsonOut([
        'loggedOut' => true,
    ]);
}

/**
 * Creates a brand-new password-only account. No passkey involved yet, this is
 * the classic signup. The user is logged in straight after, with
 * `authMethod = 'password'`.
 */
function signup(Container $container): void
{
    $body = readJson();
    $username = trim((string) ($body['username'] ?? ''));
    $password = (string) ($body['password'] ?? '');
    $displayName = trim((string) ($body['displayName'] ?? '')) ?: $username;
    if ($username === '' || $password === '') {
        throw new \RuntimeException('username and password are required.');
    }
    if (strlen($password) < 8) {
        throw new \RuntimeException('Password must be at least 8 characters long.');
    }
    if ($container->userStore->exists($username)) {
        throw new \RuntimeException('Username already taken.');
    }

    $userHandle = $container->userStore->create($username, $password, $displayName);

    $_SESSION['username'] = $username;
    $_SESSION['userHandle'] = base64_encode($userHandle);
    $_SESSION['authMethod'] = 'password';

    jsonOut([
        'signedUp' => true,
        'username' => $username,
    ]);
}

/**
 * Password sign-in. Always available, regardless of whether the account also
 * has a passkey enrolled. `authMethod` records how the user got in so the
 * account page can suggest the upgrade only to password-signed-in users that
 * have not enrolled a passkey yet.
 */
function loginPassword(Container $container): void
{
    $body = readJson();
    $username = trim((string) ($body['username'] ?? ''));
    $password = (string) ($body['password'] ?? '');
    if ($username === '' || $password === '') {
        throw new \RuntimeException('username and password are required.');
    }

    $userHandle = $container->userStore->verifyPassword($username, $password);
    if ($userHandle === null) {
        usleep(200_000);
        throw new \RuntimeException('Invalid credentials.');
    }

    $_SESSION['username'] = $username;
    $_SESSION['userHandle'] = base64_encode($userHandle);
    $_SESSION['authMethod'] = 'password';

    jsonOut([
        'verified' => true,
        'username' => $username,
        'hasPasskey' => $container->credentialStore->countForUser($userHandle) > 0,
    ]);
}

/**
 * Issue assertion options scoped to the requested account. The page calls
 * this when the user clicks "Use a passkey instead" on the login page. If no
 * passkey is registered, the endpoint returns an error so the page can
 * gracefully fall back to the password form.
 */
function loginPasskeyOptions(Container $container): void
{
    $body = readJson();
    $username = trim((string) ($body['username'] ?? ''));
    if ($username === '') {
        throw new \RuntimeException('username is required.');
    }

    $userHandle = $container->userStore->findUserHandle($username);
    if ($userHandle === null) {
        throw new \RuntimeException('Unknown user.');
    }

    $allowCredentials = $container->credentialStore->allowCredentialsFor($userHandle);
    if ($allowCredentials === []) {
        throw new \RuntimeException('No passkey enrolled for this account yet. Sign in with your password first, then add one from your account page.');
    }

    $challenge = random_bytes(32);
    $_SESSION['login_passkey_challenge'] = base64_encode($challenge);
    $_SESSION['login_passkey_username'] = $username;

    $options = PublicKeyCredentialRequestOptions::create(
        $challenge,
        $container->relyingPartyId,
        $allowCredentials,
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
    );
    $options->timeout = 60_000;

    echo serializeOptions($container, $options);
}

function loginPasskeyVerify(Container $container): void
{
    $body = file_get_contents('php://input') ?: '{}';
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');
    \assert($credential instanceof PublicKeyCredential);

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAssertionResponse) {
        throw new \RuntimeException('Expected an AuthenticatorAssertionResponse.');
    }

    $challengeB64 = $_SESSION['login_passkey_challenge'] ?? null;
    $username = (string) ($_SESSION['login_passkey_username'] ?? '');
    if (! is_string($challengeB64) || $username === '') {
        throw new \RuntimeException('Missing passkey-login session.');
    }
    $challenge = (string) base64_decode($challengeB64, true);

    $userHandle = $container->userStore->findUserHandle($username);
    if ($userHandle === null) {
        throw new \RuntimeException('Unknown user.');
    }

    $record = $container->credentialStore->findByCredentialId($credential->rawId);
    if ($record === null) {
        throw new \RuntimeException('Unknown credential for this account.');
    }

    $options = PublicKeyCredentialRequestOptions::create(
        $challenge,
        $container->relyingPartyId,
        $container->credentialStore->allowCredentialsFor($userHandle),
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
    );

    $updated = $container->assertionValidator->check(
        $record,
        $response,
        $options,
        $container->relyingPartyId,
        $userHandle,
    );
    $container->credentialStore->updateAfterAssertion($updated);

    unset($_SESSION['login_passkey_challenge'], $_SESSION['login_passkey_username']);
    $_SESSION['username'] = $username;
    $_SESSION['userHandle'] = base64_encode($userHandle);
    $_SESSION['authMethod'] = 'passkey';

    jsonOut([
        'verified' => true,
        'username' => $username,
    ]);
}

/**
 * Enrol a passkey on the logged-in account. This is the "upgrade" call: the
 * user authenticated with a password (or a previous passkey), and is now
 * adding a passkey for next time.
 *
 * Production note: if the current auth method is a weak factor (just a
 * password, no email verification step, no recent re-auth), a real RP should
 * force a re-auth before this enrolment, because anyone with the password
 * could otherwise silently bind their own passkey to the account.
 */
function addPasskeyOptions(Container $container): void
{
    $userHandle = requireLogin();
    $username = $container->userStore->findUsernameByHandle($userHandle);
    if ($username === null) {
        throw new \RuntimeException('Session out of sync. Sign in again.');
    }

    $challenge = random_bytes(32);
    $_SESSION['add_passkey_challenge'] = base64_encode($challenge);

    $options = PublicKeyCredentialCreationOptions::create(
        PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId),
        PublicKeyCredentialUserEntity::create($username, $userHandle, (string) $container->userStore->findDisplayName($username)),
        $challenge,
        [
            PublicKeyCredentialParameters::create('public-key', -7),
            PublicKeyCredentialParameters::create('public-key', -257),
        ],
        AuthenticatorSelectionCriteria::create(
            null,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
        ),
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        $container->credentialStore->excludeCredentialsFor($userHandle),
    );
    $options->timeout = 60_000;

    echo serializeOptions($container, $options);
}

function addPasskeyVerify(Container $container): void
{
    $userHandle = requireLogin();
    $username = $container->userStore->findUsernameByHandle($userHandle);
    if ($username === null) {
        throw new \RuntimeException('Session out of sync. Sign in again.');
    }

    $body = file_get_contents('php://input') ?: '{}';
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');
    \assert($credential instanceof PublicKeyCredential);

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAttestationResponse) {
        throw new \RuntimeException('Expected an AuthenticatorAttestationResponse.');
    }

    $challengeB64 = $_SESSION['add_passkey_challenge'] ?? null;
    if (! is_string($challengeB64)) {
        throw new \RuntimeException('Missing add-passkey session.');
    }
    $challenge = (string) base64_decode($challengeB64, true);

    $options = PublicKeyCredentialCreationOptions::create(
        PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId),
        PublicKeyCredentialUserEntity::create($username, $userHandle, $username),
        $challenge,
        [
            PublicKeyCredentialParameters::create('public-key', -7),
            PublicKeyCredentialParameters::create('public-key', -257),
        ],
    );

    $record = $container->attestationValidator->check($response, $options, $container->relyingPartyId);
    $label = trim((string) ($credential->clientExtensionResults['demoLabel'] ?? ''));
    if ($label === '') {
        $label = sprintf('Passkey added on %s', date('Y-m-d H:i'));
    }
    $container->credentialStore->save($userHandle, $record, $label);
    unset($_SESSION['add_passkey_challenge']);

    jsonOut([
        'verified' => true,
        'credentialId' => Base64::encode($record->publicKeyCredentialId),
    ]);
}

function renamePasskey(Container $container): void
{
    $userHandle = requireLogin();
    $body = readJson();
    $credentialId = (string) base64_decode((string) ($body['credentialId'] ?? ''), true);
    $label = trim((string) ($body['label'] ?? ''));
    if ($credentialId === '' || $label === '') {
        throw new \RuntimeException('credentialId and label are required.');
    }
    $ok = $container->credentialStore->rename($credentialId, $userHandle, $label);
    if (! $ok) {
        throw new \RuntimeException('Cannot rename this credential.');
    }
    jsonOut([
        'renamed' => true,
    ]);
}

/**
 * Allows deleting any passkey, including the last one, because the account
 * always has a password fallback. This is the upside of the upgrade flow:
 * losing every passkey is recoverable, the user just falls back to the
 * password.
 */
function deletePasskey(Container $container): void
{
    $userHandle = requireLogin();
    $body = readJson();
    $credentialId = (string) base64_decode((string) ($body['credentialId'] ?? ''), true);
    if ($credentialId === '') {
        throw new \RuntimeException('credentialId is required.');
    }
    $ok = $container->credentialStore->delete($credentialId, $userHandle);
    if (! $ok) {
        throw new \RuntimeException('Cannot delete this credential.');
    }
    jsonOut([
        'deleted' => true,
    ]);
}
