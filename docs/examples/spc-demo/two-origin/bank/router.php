<?php

declare(strict_types=1);

/**
 * Bank / Issuer / 3DS ACS server. Hosts the WebAuthn enrolment ceremony for
 * its own customers AND exposes the SPC payment-options + ACS-verify
 * endpoints that a separately-hosted merchant (cross-origin) calls during a
 * payment.
 *
 * Run with: php -S localhost:8001 -t public router.php
 */

// Same `var/` as the same-origin demo so credentials enrolled there are
// reusable. Override with VAR_DIR if you want isolation.
$_ENV['VAR_DIR'] ??= __DIR__ . '/../var';
// Allowed origins for the WebAuthn CheckOrigin step:
//   - bank.localhost:8001 (own enrolment ceremony)
//   - merchant.localhost:8002 / localhost:8002 (SPC dialog runs on the merchant origin)
$_ENV['ALLOWED_ORIGINS'] = 'http://localhost:8001,http://localhost:8002';

use App\SpcDemo\Container;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\PaymentExtension;
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
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

require_once __DIR__ . '/../../src/bootstrap.php';
require_once __DIR__ . '/../../src/CredentialStore.php';
require_once __DIR__ . '/../../src/ChallengeStore.php';

$container = new Container();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (! str_starts_with($path, '/api/')) {
    return false;
}

// CORS for the cross-origin merchant. We only allow the demo merchant
// origin; production ACS would derive trust from the 3DS network instead
// of CORS.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$merchantOrigin = 'http://localhost:8002';
if ($origin === $merchantOrigin) {
    header('Access-Control-Allow-Origin: ' . $merchantOrigin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        http_response_code(204);
        return true;
    }
}

header('Content-Type: application/json');

try {
    match ($path) {
        // Same-origin (bank's own enrolment page calls these):
        '/api/register/options' => registerOptions($container),
        '/api/register/verify' => registerVerify($container),
        // Cross-origin (merchant calls these during a payment):
        '/api/payment/options' => paymentOptions($container, $merchantOrigin),
        '/api/acs/verify' => acsVerify($container),
        default => notFound(),
    };
} catch (\Throwable $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage(), 'class' => $e::class], JSON_THROW_ON_ERROR);
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

    $userHandle = hash('sha256', 'demo:' . $username, true);
    session_start();
    $_SESSION['username'] = $username;
    $_SESSION['userHandle'] = $userHandle;

    $rpEntity = PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId);
    $userEntity = PublicKeyCredentialUserEntity::create($username, $userHandle, $username);
    $challenge = random_bytes(32);
    $_SESSION['register_challenge'] = $challenge;

    $options = PublicKeyCredentialCreationOptions::create(
        rp: $rpEntity,
        user: $userEntity,
        challenge: $challenge,
        pubKeyCredParams: [
            PublicKeyCredentialParameters::create('public-key', -7),
            PublicKeyCredentialParameters::create('public-key', -257),
        ],
        authenticatorSelection: AuthenticatorSelectionCriteria::create(
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'required',
        ),
        attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        extensions: AuthenticationExtensions::create([PaymentExtension::register()]),
    );
    $options->timeout = 60_000;

    echo $container->serializer->serialize($options, 'json', [
        'json_encode_options' => \JSON_THROW_ON_ERROR,
        \Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
    ]);
}

function registerVerify(Container $container): void
{
    session_start();
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
    if (! is_string($challenge) || $userHandle === null) {
        throw new \RuntimeException('Missing registration session — start over.');
    }

    $rpEntity = PublicKeyCredentialRpEntity::create($container->relyingPartyName, $container->relyingPartyId);
    $userEntity = PublicKeyCredentialUserEntity::create($username, $userHandle, $username);
    $options = PublicKeyCredentialCreationOptions::create(
        rp: $rpEntity,
        user: $userEntity,
        challenge: $challenge,
        pubKeyCredParams: [
            PublicKeyCredentialParameters::create('public-key', -7),
            PublicKeyCredentialParameters::create('public-key', -257),
        ],
        extensions: AuthenticationExtensions::create([PaymentExtension::register()]),
    );

    $record = $container->attestationValidator->check($response, $options, $container->relyingPartyId);
    $container->credentialStore->save($userHandle, $record);

    echo json_encode([
        'verified' => true,
        'credentialId' => Base64::encode($record->publicKeyCredentialId),
    ], JSON_THROW_ON_ERROR);
}

function paymentOptions(Container $container, string $merchantOrigin): void
{
    $body = readJson();
    $username = (string) ($body['username'] ?? '');
    $amount = (string) ($body['amount'] ?? '99.99');
    $currency = strtoupper((string) ($body['currency'] ?? 'USD'));
    $transactionId = (string) ($body['transactionId'] ?? sprintf('ORD-%s', bin2hex(random_bytes(4))));

    if ($username === '') {
        throw new \RuntimeException('username is required.');
    }

    $userHandle = hash('sha256', 'demo:' . $username, true);
    $credentialIds = $container->credentialStore->credentialIdsForUser($userHandle);
    if ($credentialIds === []) {
        throw new \RuntimeException('No credential registered for that user — go enrol on the bank site first.');
    }

    $challenge = random_bytes(32);
    $instrument = PaymentCredentialInstrument::create(
        displayName: 'FakeBank Visa •••• 1234',
        icon: 'https://placehold.co/64x64.png?text=Bank',
    );
    $total = PaymentCurrencyAmount::create(currency: $currency, value: $amount);

    // Per W3C SPC: payeeOrigin must be HTTPS — Chrome rejects http://localhost
    // here. The browser displays it in the SPC dialog but never networks to it.
    $payeeOrigin = 'https://demo-merchant.example';

    $requestOptions = PublicKeyCredentialRequestOptions::create(
        challenge: $challenge,
        rpId: $container->relyingPartyId,
        userVerification: 'required',
        allowCredentials: array_map(
            static fn (string $id): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(
                'public-key',
                Base64::decode($id),
            ),
            $credentialIds,
        ),
        extensions: AuthenticationExtensions::create([
            PaymentExtension::authenticate(
                rpId: $container->relyingPartyId,
                topOrigin: $merchantOrigin, // matches what the user agent stamps
                total: $total,
                instrument: $instrument,
                payeeName: 'Demo Merchant',
                payeeOrigin: $payeeOrigin,
            ),
        ]),
    );
    $requestOptions->timeout = 60_000;

    $challengeKey = Base64UrlSafe::encodeUnpadded($challenge);
    $container->challengeStore->put($challengeKey, [
        'transactionId' => $transactionId,
        'userHandle' => $userHandle,
        'requestOptions' => $container->serializer->serialize($requestOptions, 'json'),
    ]);

    echo json_encode([
        'rpId' => $container->relyingPartyId,
        'transactionId' => $transactionId,
        'challenge' => Base64UrlSafe::encodeUnpadded($challenge),
        'credentialIds' => array_map(
            static fn (string $id): string => Base64UrlSafe::encodeUnpadded(Base64::decode($id)),
            $credentialIds,
        ),
        'instrument' => [
            'displayName' => $instrument->displayName,
            'icon' => $instrument->icon,
        ],
        'payeeName' => 'Demo Merchant',
        'payeeOrigin' => $payeeOrigin,
        'total' => [
            'currency' => $currency,
            'value' => $amount,
        ],
        'timeout' => 60_000,
    ], JSON_THROW_ON_ERROR);
}

function acsVerify(Container $container): void
{
    $body = file_get_contents('php://input') ?: '{}';
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');
    \assert($credential instanceof PublicKeyCredential);

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAssertionResponse) {
        throw new \RuntimeException('Expected an AuthenticatorAssertionResponse.');
    }

    $challengeKey = Base64UrlSafe::encodeUnpadded($response->clientDataJSON->challenge);
    $context = $container->challengeStore->pop($challengeKey);
    if ($context === null) {
        throw new \RuntimeException('Unknown challenge — request expired or never issued.');
    }

    $requestOptions = $container->serializer->deserialize(
        $context['requestOptions'],
        PublicKeyCredentialRequestOptions::class,
        'json',
    );
    \assert($requestOptions instanceof PublicKeyCredentialRequestOptions);

    $credentialSource = $container->credentialStore->findByCredentialId($credential->rawId);
    if ($credentialSource === null) {
        // 3DS would surface this as transStatus=R (rejected, unknown card).
        throw new \RuntimeException('Unknown credential.');
    }

    // The signature math + PaymentClientDataCollector + PaymentExtensionOutputChecker +
    // CheckBrowserBoundSignature run inside ->check(). On success the bank
    // knows: this exact transaction was authorised by this exact user on
    // this exact authenticator AND the browser-bound signature is
    // cryptographically valid against the COSE key Chrome ships in
    // clientDataJSON.payment.browserBoundPublicKey.
    $updatedRecord = $container->assertionValidator->check(
        $credentialSource,
        $response,
        $requestOptions,
        $container->relyingPartyId,
        $context['userHandle'],
    );
    $container->credentialStore->updateAfterAssertion($updatedRecord);

    /** @var array<string, mixed> $signedPayment */
    $signedPayment = $response->clientDataJSON->get('payment');
    $browserBoundKeyPresent = is_string($signedPayment['browserBoundPublicKey'] ?? null);

    echo json_encode([
        // Mock 3DS2 ARes shape — see README for the real-vs-synthesized split.
        'transStatus' => 'Y',
        'eci' => '05',
        'authenticationValue' => base64_encode(random_bytes(20)), // mock CAVV
        'transactionId' => $context['transactionId'],
        'cardholderName' => 'Demo Cardholder',
        // Real, cryptographically-bound:
        'signedPayment' => $signedPayment,
        'browserBoundSignatureVerified' => $browserBoundKeyPresent,
    ], JSON_THROW_ON_ERROR);
}
