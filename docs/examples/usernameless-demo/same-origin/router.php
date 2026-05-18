<?php

declare(strict_types=1);

/**
 * Front controller for `php -S`. Same shape as the basic-demo, plus the
 * usernameless-specific differences:
 *
 *  - /api/register/options forces `residentKey: required` and
 *    `userVerification: required` so the credential is discoverable and the
 *    authenticator stores the user handle locally;
 *  - /api/login/options does NOT take a username. The server issues a
 *    challenge with an empty `allowCredentials` list, the browser uses the
 *    `mediation: 'conditional'` UI mode to surface a passkey picker;
 *  - /api/login/verify resolves the user via the credential id and verifies
 *    that `response.userHandle` matches the binding stored at registration.
 *
 * Run with: php -S localhost:8000 -t public router.php
 */

use App\UsernamelessDemo\Container;
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
        '/api/register/options' => registerOptions($container),
        '/api/register/verify' => registerVerify($container),
        '/api/login/options' => loginOptions($container),
        '/api/login/verify' => loginVerify($container),
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
 * Step 1 of registration: server generates the creation options.
 *
 * Two flags drive the usernameless behaviour:
 *
 *  - `residentKey: required` tells the authenticator to store a discoverable
 *    credential, which keeps the user handle on the device and lets the
 *    browser surface the account on a future Conditional UI prompt without
 *    being told a username;
 *  - `userVerification: required` makes the authenticator perform user
 *    verification (biometric, PIN, ...) at every ceremony. This is what
 *    turns the credential into a single-factor passkey instead of a
 *    second factor.
 */
function registerOptions(Container $container): void
{
    $body = readJson();
    $username = trim((string) ($body['username'] ?? ''));
    $displayName = trim((string) ($body['displayName'] ?? '')) ?: $username;
    if ($username === '') {
        throw new \RuntimeException('username is required.');
    }

    $userHandle = $container->userStore->findOrCreate($username, $displayName);
    $_SESSION['register_username'] = $username;
    $_SESSION['register_userHandle'] = base64_encode($userHandle);

    $challenge = random_bytes(32);
    $_SESSION['register_challenge'] = base64_encode($challenge);

    $options = PublicKeyCredentialCreationOptions::create(
        PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId),
        PublicKeyCredentialUserEntity::create($username, $userHandle, $displayName),
        $challenge,
        [
            PublicKeyCredentialParameters::create('public-key', -7),
            PublicKeyCredentialParameters::create('public-key', -257),
        ],
        AuthenticatorSelectionCriteria::create(
            null,
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        ),
        PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        $container->credentialStore->excludeCredentialsFor($userHandle),
    );
    $options->timeout = 60_000;

    echo serializeOptions($container, $options);
}

function registerVerify(Container $container): void
{
    $body = file_get_contents('php://input') ?: '{}';
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');
    \assert($credential instanceof PublicKeyCredential);

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAttestationResponse) {
        throw new \RuntimeException('Expected an AuthenticatorAttestationResponse.');
    }

    $challengeB64 = $_SESSION['register_challenge'] ?? null;
    $username = (string) ($_SESSION['register_username'] ?? '');
    $userHandleB64 = $_SESSION['register_userHandle'] ?? null;
    if (! is_string($challengeB64) || $username === '' || ! is_string($userHandleB64)) {
        throw new \RuntimeException('Missing registration session. Start over from /register.html.');
    }
    $challenge = (string) base64_decode($challengeB64, true);
    $userHandle = (string) base64_decode($userHandleB64, true);

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

    unset($_SESSION['register_challenge'], $_SESSION['register_username'], $_SESSION['register_userHandle']);
    $_SESSION['username'] = $username;
    $_SESSION['userHandle'] = $userHandleB64;

    jsonOut([
        'verified' => true,
        'credentialId' => Base64::encode($record->publicKeyCredentialId),
    ]);
}

/**
 * Step 1 of login: server hands out a challenge with an empty
 * `allowCredentials` list. The page asks the user agent to surface a
 * Conditional UI prompt, which lets the user pick any discoverable
 * credential bound to this relying party (rpId). No username known to the
 * server yet.
 */
function loginOptions(Container $container): void
{
    $challenge = random_bytes(32);
    $_SESSION['login_challenge'] = base64_encode($challenge);

    $options = PublicKeyCredentialRequestOptions::create(
        $challenge,
        $container->relyingPartyId,
        [],
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
    );
    $options->timeout = 60_000;

    echo serializeOptions($container, $options);
}

/**
 * Step 2 of login: resolve the user from the credential.
 *
 * The browser includes `response.userHandle` because the authenticator was
 * enrolled as a discoverable credential. We use the credential id to fetch
 * the stored CredentialRecord, then verify that the stored userHandle
 * matches the one the authenticator returned, then hand both to the
 * assertion validator (which double-checks the binding on its own).
 */
function loginVerify(Container $container): void
{
    $body = file_get_contents('php://input') ?: '{}';
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');
    \assert($credential instanceof PublicKeyCredential);

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAssertionResponse) {
        throw new \RuntimeException('Expected an AuthenticatorAssertionResponse.');
    }

    $challengeB64 = $_SESSION['login_challenge'] ?? null;
    if (! is_string($challengeB64)) {
        throw new \RuntimeException('Missing login session. Start over from /login.html.');
    }
    $challenge = (string) base64_decode($challengeB64, true);

    $record = $container->credentialStore->findByCredentialId($credential->rawId);
    if ($record === null) {
        throw new \RuntimeException('Unknown credential.');
    }
    $storedUserHandle = $container->credentialStore->findUserHandleByCredentialId($credential->rawId);
    if ($storedUserHandle === null) {
        throw new \RuntimeException('Credential is not bound to any user.');
    }
    $username = $container->userStore->findUsernameByHandle($storedUserHandle);
    if ($username === null) {
        throw new \RuntimeException('User no longer exists.');
    }

    if ($response->userHandle === null || $response->userHandle === '') {
        throw new \RuntimeException('Authenticator did not return a user handle. Discoverable-credential ceremonies require it.');
    }
    if (! hash_equals($storedUserHandle, $response->userHandle)) {
        throw new \RuntimeException('User handle mismatch between authenticator and server-stored record.');
    }

    $options = PublicKeyCredentialRequestOptions::create(
        $challenge,
        $container->relyingPartyId,
        [],
        PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
    );

    $updated = $container->assertionValidator->check(
        $record,
        $response,
        $options,
        $container->relyingPartyId,
        $storedUserHandle,
    );
    $container->credentialStore->updateAfterAssertion($updated);

    unset($_SESSION['login_challenge']);
    $_SESSION['username'] = $username;
    $_SESSION['userHandle'] = base64_encode($storedUserHandle);

    jsonOut([
        'verified' => true,
        'username' => $username,
    ]);
}

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
            AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
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

function deletePasskey(Container $container): void
{
    $userHandle = requireLogin();
    $body = readJson();
    $credentialId = (string) base64_decode((string) ($body['credentialId'] ?? ''), true);
    if ($credentialId === '') {
        throw new \RuntimeException('credentialId is required.');
    }
    if ($container->credentialStore->countForUser($userHandle) <= 1) {
        throw new \RuntimeException('Cannot delete the last passkey of this account.');
    }
    $ok = $container->credentialStore->delete($credentialId, $userHandle);
    if (! $ok) {
        throw new \RuntimeException('Cannot delete this credential.');
    }
    jsonOut([
        'deleted' => true,
    ]);
}
