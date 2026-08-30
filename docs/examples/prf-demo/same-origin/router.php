<?php

declare(strict_types=1);

/**
 * Front controller for `php -S`. Routes the API endpoints; for every other
 * request it returns false so the built-in server falls back to serving the
 * matching static file from `public/`.
 *
 * Run with: php -S localhost:8000 -t public router.php
 */

use App\PrfDemo\Container;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\PseudoRandomFunctionInputExtensionBuilder;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/../src/CredentialStore.php';

session_start();
$container = new Container();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (! str_starts_with($path, '/api/')) {
    return false;
}

header('Content-Type: application/json');

try {
    match ($path) {
        '/api/register/options' => registerOptions($container),
        '/api/register/verify' => registerVerify($container),
        '/api/vault/options' => vaultOptions($container),
        '/api/vault/verify' => vaultVerify($container),
        '/api/vault/items/add' => vaultItemAdd($container),
        '/api/vault/items/delete' => vaultItemDelete($container),
        default => notFound(),
    };
} catch (\Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'error' => $e->getMessage(),
        'class' => $e::class,
    ], JSON_THROW_ON_ERROR);
}

function notFound(): void
{
    http_response_code(404);
    echo json_encode(['error' => 'Not found'], JSON_THROW_ON_ERROR);
}

/**
 * @return array<string, mixed>
 */
function readJson(): array
{
    $body = file_get_contents('php://input') ?: '{}';
    $json = json_decode($body, true, flags: JSON_THROW_ON_ERROR);

    return is_array($json) ? $json : [];
}

function registerOptions(Container $container): void
{
    $body = readJson();
    $username = (string) ($body['username'] ?? 'jane.doe@example.com');

    // Stable user handle for the demo. In a real app this comes from your user table.
    $userHandle = hash('sha256', 'demo:' . $username, true);
    $_SESSION['username'] = $username;
    $_SESSION['userHandle'] = $userHandle;

    $challenge = random_bytes(32);
    $_SESSION['register_challenge'] = $challenge;

    // The PRF salts are per-credential, generated at registration and persisted by the
    // server so they can be re-issued at every authentication. The salts are NOT secrets
    // (they are sent to the browser in plaintext on every ceremony); the secret is the
    // PRF *output* the authenticator derives from the salt and the credential-bound
    // secret it holds. That output stays in the browser: the spec forbids authenticator
    // extension outputs from carrying cleartext PRF results.
    //
    // The spec lets you pass two salts per ceremony — `first` and `second`. The
    // authenticator computes the PRF over both in a single round-trip, the page gets
    // both outputs back. The demo derives its AES-GCM key from `first` and leaves
    // `second` for additional derivations (HMAC, secondary key, key rotation, …).
    $prfSalt = random_bytes(32);
    $prfSalt2 = random_bytes(32);
    $_SESSION['register_prf_salt'] = $prfSalt;
    $_SESSION['register_prf_salt2'] = $prfSalt2;

    $options = PublicKeyCredentialCreationOptions::create(
        rp: PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId),
        user: PublicKeyCredentialUserEntity::create($username, $userHandle, $username),
        challenge: $challenge,
        pubKeyCredParams: [
            PublicKeyCredentialParameters::create('public-key', -7),    // ES256
            PublicKeyCredentialParameters::create('public-key', -257),  // RS256
        ],
        authenticatorSelection: \Webauthn\AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'required',
        ),
        attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        extensions: AuthenticationExtensions::create([
            // PRF at registration: the spec only guarantees `prf.enabled: true|false`
            // back from the authenticator. Actual PRF *outputs* at registration time
            // depend on the platform — set the salts anyway so the page can detect
            // support and surface it in the UI before the user navigates to the
            // vault page.
            PseudoRandomFunctionInputExtensionBuilder::create()
                ->withInputs($prfSalt, $prfSalt2)
                ->build(),
        ]),
    );
    $options->timeout = 60_000;

    echo $container->serializer->serialize($options, 'json', [
        'json_encode_options' => \JSON_THROW_ON_ERROR,
        \Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
    ]);
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

    $challenge = $_SESSION['register_challenge'] ?? null;
    $username = (string) ($_SESSION['username'] ?? '');
    $userHandle = $_SESSION['userHandle'] ?? null;
    $prfSalt = $_SESSION['register_prf_salt'] ?? null;
    $prfSalt2 = $_SESSION['register_prf_salt2'] ?? null;
    if (! is_string($challenge) || $userHandle === null || ! is_string($prfSalt) || ! is_string($prfSalt2)) {
        throw new \RuntimeException('Missing registration session — start over.');
    }

    $options = PublicKeyCredentialCreationOptions::create(
        rp: PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId),
        user: PublicKeyCredentialUserEntity::create($username, $userHandle, $username),
        challenge: $challenge,
        pubKeyCredParams: [
            PublicKeyCredentialParameters::create('public-key', -7),
            PublicKeyCredentialParameters::create('public-key', -257),
        ],
    );

    $record = $container->attestationValidator->check($response, $options, $container->relyingPartyId);
    $container->credentialStore->save($userHandle, $record, $prfSalt, $prfSalt2);

    echo json_encode([
        'verified' => true,
        'credentialId' => Base64::encode($record->publicKeyCredentialId),
    ], JSON_THROW_ON_ERROR);
}

function vaultOptions(Container $container): void
{
    $body = readJson();
    $username = (string) ($body['username'] ?? '');
    if ($username === '') {
        throw new \RuntimeException('username is required.');
    }

    $userHandle = hash('sha256', 'demo:' . $username, true);
    $credentialIds = $container->credentialStore->credentialIdsForUser($userHandle);
    if ($credentialIds === []) {
        throw new \RuntimeException('No credential registered for that user — register first.');
    }

    $challenge = random_bytes(32);
    $_SESSION['vault_challenge'] = $challenge;
    $_SESSION['vault_username'] = $username;

    // Re-issue each credential's stored salt as the per-credential PRF input. The
    // browser will receive the same bytes the authenticator was queried with at
    // registration → the PRF output is identical → the AES-GCM key is identical →
    // every ciphertext stored under that credential decrypts.
    $prfBuilder = PseudoRandomFunctionInputExtensionBuilder::create();
    $allowCredentials = [];
    $items = [];
    foreach ($credentialIds as $idB64) {
        $rawId = (string) base64_decode($idB64, true);
        $stored = $container->credentialStore->findByCredentialId($rawId);
        if ($stored === null) {
            continue;
        }
        $allowCredentials[] = PublicKeyCredentialDescriptor::create('public-key', $rawId);
        $credIdB64Url = Base64UrlSafe::encodeUnpadded($rawId);
        // Re-issue both salts so the page recomputes both PRF outputs in a single
        // authenticator round-trip. `second` is empty for legacy rows registered
        // before the dual-salt update — fall back to first-salt-only in that case.
        if ($stored['prfSalt2'] !== '') {
            $prfBuilder->withCredentialInputs($credIdB64Url, $stored['prfSalt'], $stored['prfSalt2']);
        } else {
            $prfBuilder->withCredentialInputs($credIdB64Url, $stored['prfSalt']);
        }
        $items[$credIdB64Url] = $stored['items'];
    }

    $options = PublicKeyCredentialRequestOptions::create(
        challenge: $challenge,
        rpId: $container->relyingPartyId,
        userVerification: 'required',
        allowCredentials: $allowCredentials,
        extensions: AuthenticationExtensions::create([$prfBuilder->build()]),
    );
    $options->timeout = 60_000;

    echo json_encode([
        'options' => json_decode($container->serializer->serialize($options, 'json', [
            'json_encode_options' => \JSON_THROW_ON_ERROR,
            \Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]), true, flags: JSON_THROW_ON_ERROR),
        // Hand the stored items back at the same time so the browser can decrypt
        // them right after the assertion completes. Sent in clear; without the
        // PRF-derived key they are just noise.
        'itemsByCredential' => $items,
    ], JSON_THROW_ON_ERROR);
}

function vaultVerify(Container $container): void
{
    $body = file_get_contents('php://input') ?: '{}';
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');
    \assert($credential instanceof PublicKeyCredential);

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAssertionResponse) {
        throw new \RuntimeException('Expected an AuthenticatorAssertionResponse.');
    }

    $challenge = $_SESSION['vault_challenge'] ?? null;
    if (! is_string($challenge)) {
        throw new \RuntimeException('Missing vault session — start over.');
    }

    $rawId = $credential->rawId;
    $stored = $container->credentialStore->findByCredentialId($rawId);
    if ($stored === null) {
        throw new \RuntimeException('Unknown credential.');
    }
    $userHandle = $container->credentialStore->findUserHandleByCredentialId($rawId);

    $options = PublicKeyCredentialRequestOptions::create(
        challenge: $challenge,
        rpId: $container->relyingPartyId,
        userVerification: 'required',
    );

    $updatedRecord = $container->assertionValidator->check(
        $stored['record'],
        $response,
        $options,
        $container->relyingPartyId,
        $userHandle,
    );
    $container->credentialStore->updateAfterAssertion($updatedRecord);

    // Mark the vault unlocked for this credential. Subsequent add/delete calls
    // require this flag — without it any cookie holder could pollute another
    // user's vault. The flag is bound to the assertion challenge, so it expires
    // naturally once the next /api/vault/options is called (which rotates it).
    $_SESSION['vault_unlocked'] = base64_encode($rawId);

    echo json_encode([
        'verified' => true,
        'credentialId' => Base64::encode($rawId),
    ], JSON_THROW_ON_ERROR);
}

function requireUnlocked(): string
{
    $unlocked = $_SESSION['vault_unlocked'] ?? null;
    if (! is_string($unlocked) || $unlocked === '') {
        throw new \RuntimeException('Vault is locked — authenticate first.');
    }

    return (string) base64_decode($unlocked, true);
}

function vaultItemAdd(Container $container): void
{
    $credentialId = requireUnlocked();
    $body = readJson();
    $label = trim((string) ($body['label'] ?? ''));
    $ciphertext = (string) ($body['ciphertext'] ?? '');
    $iv = (string) ($body['iv'] ?? '');
    $mac = (string) ($body['mac'] ?? '');
    if ($label === '' || $ciphertext === '' || $iv === '' || $mac === '') {
        throw new \RuntimeException('label, ciphertext, iv and mac are all required.');
    }

    $id = $container->credentialStore->appendItem($credentialId, $label, $ciphertext, $iv, $mac);

    echo json_encode([
        'id' => $id,
        'label' => $label,
        'ciphertext' => $ciphertext,
        'iv' => $iv,
        'mac' => $mac,
    ], JSON_THROW_ON_ERROR);
}

function vaultItemDelete(Container $container): void
{
    $credentialId = requireUnlocked();
    $body = readJson();
    $itemId = (string) ($body['id'] ?? '');
    if ($itemId === '') {
        throw new \RuntimeException('id is required.');
    }

    $container->credentialStore->deleteItem($credentialId, $itemId);

    echo json_encode(['deleted' => $itemId], JSON_THROW_ON_ERROR);
}
