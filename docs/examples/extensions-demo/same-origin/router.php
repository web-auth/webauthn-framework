<?php

declare(strict_types=1);

/**
 * Single-file PHP router for the extensions demo. Run with:
 *   php -S 0.0.0.0:8000 -t public router.php
 *
 * Endpoints:
 *   POST /register/options     → PublicKeyCredentialCreationOptions JSON
 *   POST /register/result      → verify the attestation, persist + show outputs
 *   POST /assert/options       → PublicKeyCredentialRequestOptions JSON
 *                                 (sets getCredBlob:true to request the blob back)
 *   POST /assert/result        → verify the assertion, return the retrieved blob
 *
 * Static files under public/ are served by the built-in server directly.
 */

use App\ExtensionsDemo\Container;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\CredentialBlobInputExtension;
use Webauthn\AuthenticationExtensions\CredentialBlobAssertionOutput;
use Webauthn\AuthenticationExtensions\CredentialBlobRegistrationOutput;
use Webauthn\AuthenticationExtensions\CredentialPropertiesInputExtension;
use Webauthn\AuthenticationExtensions\CredentialPropertiesOutput;
use Webauthn\AuthenticationExtensions\CredentialProtectionInputExtension;
use Webauthn\AuthenticationExtensions\CredentialProtectionOutput;
use Webauthn\AuthenticationExtensions\GetCredentialBlobInputExtension;
use Webauthn\AuthenticationExtensions\MinPinLengthInputExtension;
use Webauthn\AuthenticationExtensions\MinPinLengthOutput;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

require_once __DIR__ . '/../src/CredentialStore.php';
require_once __DIR__ . '/../src/bootstrap.php';

$container = new Container();
$container->allowedOrigins = ['http://localhost:8000', 'https://localhost:8000'];

// Let the built-in server serve static files directly. Map "/" → "/index.html"
// so the landing page works without a redirect, and let it handle any other
// existing file under public/.
$path = parse_url($_SERVER['REQUEST_URI'], \PHP_URL_PATH);
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $resolved = $path === '/' || str_ends_with($path, '/') ? rtrim($path, '/') . '/index.html' : $path;
    if (is_file(__DIR__ . '/public' . $resolved)) {
        if ($resolved !== $path) {
            // Have the built-in server serve the resolved file by rewriting
            // the request before returning false.
            $_SERVER['REQUEST_URI'] = $resolved;
            $_SERVER['SCRIPT_NAME'] = $resolved;
        }
        return false;
    }
}

session_start();

header('Content-Type: application/json');
header('Cache-Control: no-store');

try {
    if ($path === '/register/options') {
        echo json_encode(handleRegistrationOptions($container));
        return;
    }
    if ($path === '/register/result') {
        echo json_encode(handleRegistrationResult($container));
        return;
    }
    if ($path === '/assert/options') {
        echo json_encode(handleAssertionOptions($container));
        return;
    }
    if ($path === '/assert/result') {
        echo json_encode(handleAssertionResult($container));
        return;
    }
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'error' => $e->getMessage(),
        'class' => $e::class,
    ]);
    return;
}

http_response_code(404);
echo json_encode(['error' => 'Not found']);

/* -------------------------------------------------------------------------- */
/*  Registration                                                              */
/* -------------------------------------------------------------------------- */

/**
 * @return array{options: array<string, mixed>}
 */
function handleRegistrationOptions(Container $container): array
{
    $body = readJsonBody();
    $username = (string) ($body['username'] ?? 'alice');
    $policy = $body['credProtect'] ?? null; // userVerificationOptional | userVerificationOptionalWithCredentialIDList | userVerificationRequired
    $blob = (string) ($body['credBlob'] ?? '');

    // Defensive: another demo on http://localhost may have stored a different
    // shape under the same session cookie. Reset if it isn't an array.
    if (! isset($_SESSION['userHandle']) || ! is_array($_SESSION['userHandle'])) {
        $_SESSION['userHandle'] = [];
    }
    $userHandle = $_SESSION['userHandle'][$username] ?? random_bytes(16);
    $_SESSION['userHandle'][$username] = $userHandle;

    $extensions = [
        // L3 §10.1.3: ask the UA for credProps so we can read back
        // {rk, authenticatorDisplayName} after registration.
        CredentialPropertiesInputExtension::enable(),
        // CTAP 2.1 §12.4: ask the authenticator for its configured min PIN length.
        MinPinLengthInputExtension::enable(),
    ];

    if (in_array($policy, CredentialProtectionInputExtension::POLICIES, true)) {
        $extensions[] = match ($policy) {
            CredentialProtectionInputExtension::POLICY_USER_VERIFICATION_OPTIONAL => CredentialProtectionInputExtension::userVerificationOptional(),
            CredentialProtectionInputExtension::POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST => CredentialProtectionInputExtension::userVerificationOptionalWithCredentialIDList(),
            CredentialProtectionInputExtension::POLICY_USER_VERIFICATION_REQUIRED => CredentialProtectionInputExtension::userVerificationRequired(),
        };
        // Only ask the UA to fail-rather-than-downgrade when we requested a
        // policy STRONGER than the spec default (level 1). With level 1 +
        // enforce, modern passkey-capable authenticators (iCloud Keychain,
        // Windows Hello, Android) refuse with "Requested protection policy
        // is inconsistent or incongruent with other requested parameters",
        // because they create a discoverable credential by default and that
        // requires credProtect ≥ level 2 — incompatible with our enforce on
        // level 1.
        if ($policy !== CredentialProtectionInputExtension::POLICY_USER_VERIFICATION_OPTIONAL) {
            $extensions[] = CredentialProtectionInputExtension::enforce();
        }
    }

    if ($blob !== '') {
        // CTAP 2.1 §12.2: store ≤32 bytes alongside the credential.
        $extensions[] = CredentialBlobInputExtension::withBlob($blob);
    }

    // CTAP 2.1 §12.1 — the requested credProtect policy MUST be consistent with
    // the AuthenticatorSelectionCriteria, otherwise the authenticator returns
    // CTAP2_ERR_REQUEST_TOO_LARGE / "Requested protection policy is inconsistent":
    //   - userVerificationOptionalWithCredentialIDList → resident key required
    //   - userVerificationRequired                     → resident key required + UV required
    $authenticatorSelection = match ($policy) {
        CredentialProtectionInputExtension::POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST => AuthenticatorSelectionCriteria::create(
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        ),
        CredentialProtectionInputExtension::POLICY_USER_VERIFICATION_REQUIRED => AuthenticatorSelectionCriteria::create(
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        ),
        default => null,
    };

    $options = PublicKeyCredentialCreationOptions::create(
        rp: PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId),
        user: PublicKeyCredentialUserEntity::create($username, $userHandle, $username),
        challenge: random_bytes(32),
        pubKeyCredParams: [
            PublicKeyCredentialParameters::create('public-key', -7),  // ES256
            PublicKeyCredentialParameters::create('public-key', -257), // RS256
        ],
        authenticatorSelection: $authenticatorSelection,
        attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        extensions: AuthenticationExtensions::create($extensions),
    );
    $options->timeout = 60_000;

    $_SESSION['register']['options'] = $container->serializer->serialize($options, 'json');
    $_SESSION['register']['username'] = $username;
    $_SESSION['register']['userHandle'] = $userHandle;
    $_SESSION['register']['requestedCredProtect'] = $policy;
    $_SESSION['register']['credBlob'] = $blob;

    return [
        'options' => json_decode($container->serializer->serialize($options, 'json'), true),
    ];
}

/**
 * @return array<string, mixed>
 */
function handleRegistrationResult(Container $container): array
{
    $body = readRawBody();
    $bodyData = json_decode($body, true);
    if (! is_array($bodyData)) {
        throw new RuntimeException('Invalid JSON body.');
    }
    $serialized = $_SESSION['register']['options'] ?? null;
    if ($serialized === null) {
        throw new RuntimeException('No registration in progress.');
    }
    /** @var PublicKeyCredentialCreationOptions $options */
    $options = $container->serializer->deserialize($serialized, PublicKeyCredentialCreationOptions::class, 'json');

    /** @var PublicKeyCredential $credential */
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAttestationResponse) {
        throw new RuntimeException('Expected an attestation response.');
    }

    $record = $container->attestationValidator->check($response, $options, $container->relyingPartyId);

    // Parse what the user agent actually returned for each extension we
    // requested. NB: $body is the raw JSON STRING — read clientExtensionResults
    // off the decoded array, not the string (PHP 8 silently drops the
    // string-key access on a string and we lose every extension output).
    $clientExtAssoc = is_array($bodyData['clientExtensionResults'] ?? null) ? $bodyData['clientExtensionResults'] : [];

    $clientExtensions = AuthenticationExtensions::create(array_map(
        static fn (string $name, mixed $value): AuthenticationExtension => AuthenticationExtension::create($name, $value),
        array_keys($clientExtAssoc),
        array_values($clientExtAssoc),
    ));

    $authenticatorExtensions = $response->attestationObject->authData->extensions ?? AuthenticationExtensions::create();

    $credProps = CredentialPropertiesOutput::fromExtensions($clientExtensions);
    $minPinLength = MinPinLengthOutput::fromExtensions($authenticatorExtensions);
    $credProtect = CredentialProtectionOutput::fromExtensions($authenticatorExtensions);
    $credBlobReg = CredentialBlobRegistrationOutput::fromExtensions($authenticatorExtensions);

    $registrationOutputs = [
        'credProps' => $credProps === null ? null : [
            'rk' => $credProps->rk,
            'authenticatorDisplayName' => $credProps->authenticatorDisplayName,
        ],
        'minPinLength' => $minPinLength?->minPinLength,
        'credProtect' => $credProtect === null ? null : credProtectLabel($credProtect->policy),
        'credBlob' => $credBlobReg?->stored,
    ];

    $container->credentialStore->save(
        $record,
        base64_encode($record->publicKeyCredentialId),
        bin2hex($_SESSION['register']['userHandle']),
        $_SESSION['register']['requestedCredProtect'],
        $_SESSION['register']['credBlob'],
        $registrationOutputs,
    );

    // What we actually asked the user agent for (so the result page can
    // distinguish "not requested" from "requested but the authenticator
    // declined to return it").
    $requested = [
        'credProps' => true,
        'minPinLength' => true,
        'credProtect' => $_SESSION['register']['requestedCredProtect'],
        'credBlob' => $_SESSION['register']['credBlob'] !== '',
    ];

    // Raw extension bags as the authenticator / user agent emitted them.
    // Surfaced verbatim so the user can see what really came back vs what
    // the typed value objects parsed.
    $rawAuthenticator = [];
    foreach ($authenticatorExtensions as $name => $extension) {
        $rawAuthenticator[$name] = $extension->value;
    }

    unset($_SESSION['register']);

    return [
        'verified' => true,
        'credentialId' => Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId),
        'extensionOutputs' => $registrationOutputs,
        'requested' => $requested,
        'rawAuthenticatorExtensions' => $rawAuthenticator,
        'rawClientExtensions' => $clientExtAssoc,
    ];
}

/* -------------------------------------------------------------------------- */
/*  Assertion                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * @return array{options: array<string, mixed>, allowed: list<array{credentialId: string, requestedCredProtect: ?string, credBlob: string}>}
 */
function handleAssertionOptions(Container $container): array
{
    $allowed = [];
    $allowCredentials = [];
    foreach ($container->credentialStore->all() as $row) {
        $rawId = (string) base64_decode($row['credentialId'], true);
        $allowCredentials[] = PublicKeyCredentialDescriptor::create('public-key', $rawId);
        $allowed[] = [
            'credentialId' => $row['credentialId'],
            'requestedCredProtect' => $row['requestedCredProtect'],
            'credBlob' => $row['credBlob'],
        ];
    }

    if ($allowCredentials === []) {
        throw new RuntimeException('Register a credential first.');
    }

    $options = PublicKeyCredentialRequestOptions::create(
        challenge: random_bytes(32),
        rpId: $container->relyingPartyId,
        allowCredentials: $allowCredentials,
        userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        extensions: AuthenticationExtensions::create([
            // CTAP 2.1 §12.2: ask the authenticator to return the previously stored blob.
            GetCredentialBlobInputExtension::enable(),
        ]),
    );
    $options->timeout = 60_000;

    $_SESSION['assert']['options'] = $container->serializer->serialize($options, 'json');

    return [
        'options' => json_decode($container->serializer->serialize($options, 'json'), true),
        'allowed' => $allowed,
    ];
}

/**
 * @return array<string, mixed>
 */
function handleAssertionResult(Container $container): array
{
    $body = readRawBody();
    $serialized = $_SESSION['assert']['options'] ?? null;
    if ($serialized === null) {
        throw new RuntimeException('No assertion in progress.');
    }
    /** @var PublicKeyCredentialRequestOptions $options */
    $options = $container->serializer->deserialize($serialized, PublicKeyCredentialRequestOptions::class, 'json');

    /** @var PublicKeyCredential $credential */
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAssertionResponse) {
        throw new RuntimeException('Expected an assertion response.');
    }

    $stored = $container->credentialStore->findByCredentialId($credential->rawId);
    if ($stored === null) {
        throw new RuntimeException('Unknown credential.');
    }

    $userHandle = $response->userHandle ?? $stored->userHandle;
    $updated = $container->assertionValidator->check(
        $stored,
        $response,
        $options,
        $container->relyingPartyId,
        $userHandle,
    );
    $container->credentialStore->update($updated);

    $authenticatorExtensions = $response->authenticatorData->extensions ?? AuthenticationExtensions::create();
    $credBlob = CredentialBlobAssertionOutput::fromExtensions($authenticatorExtensions);

    unset($_SESSION['assert']);

    return [
        'verified' => true,
        'credBlob' => $credBlob === null ? null : Base64UrlSafe::encodeUnpadded($credBlob->blob),
        'credBlobUtf8' => $credBlob === null ? null : @mb_convert_encoding($credBlob->blob, 'UTF-8', 'UTF-8'),
    ];
}

/* -------------------------------------------------------------------------- */

function credProtectLabel(int $policy): string
{
    return match ($policy) {
        CredentialProtectionOutput::POLICY_USER_VERIFICATION_OPTIONAL => 'userVerificationOptional',
        CredentialProtectionOutput::POLICY_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST => 'userVerificationOptionalWithCredentialIDList',
        CredentialProtectionOutput::POLICY_USER_VERIFICATION_REQUIRED => 'userVerificationRequired',
    };
}

function readJsonBody(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === '' || $raw === false) {
        return [];
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function readRawBody(): string
{
    $raw = file_get_contents('php://input');
    return $raw === false ? '' : $raw;
}
