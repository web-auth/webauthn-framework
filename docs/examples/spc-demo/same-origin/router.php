<?php

declare(strict_types=1);

/**
 * Front controller for `php -S`. Routes the 4 API endpoints; for every other
 * request it returns false so the built-in server falls back to serving the
 * matching static file from `public/`.
 *
 * Run with: php -S localhost:8000 -t public router.php
 */

use App\SpcDemo\Container;
use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\PaymentExtension;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;

require_once __DIR__ . '/../src/bootstrap.php';
require_once __DIR__ . '/../src/CredentialStore.php';
require_once __DIR__ . '/../src/ChallengeStore.php';

session_start();
$container = new Container();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// Let the built-in server serve static files itself.
if (! str_starts_with($path, '/api/')) {
    return false;
}

header('Content-Type: application/json');

try {
    match ($path) {
        '/api/register/options' => registerOptions($container),
        '/api/register/verify' => registerVerify($container),
        '/api/payment/options' => paymentOptions($container),
        '/api/payment/verify' => paymentVerify($container),
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

    // The RP server identifies the user. In a real app this lookup hits
    // your user database; we just derive a stable handle from the username.
    $userHandle = hash('sha256', 'demo:' . $username, true);
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
            // Per W3C SPC §5: registration only needs `isPayment: true` to
            // enable the credential for cross-origin payment authentication.
            PaymentExtension::register(),
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

function paymentOptions(Container $container): void
{
    $body = readJson();
    $username = (string) ($body['username'] ?? '');
    $amount = (string) ($body['amount'] ?? '99.99');
    $currency = strtoupper((string) ($body['currency'] ?? 'USD'));
    // Merchant-side correlation key (order ID, cart ID, …). The user does
    // not see or sign this — it is bound to the WebAuthn challenge
    // server-side so we can recover it after the assertion comes back.
    $transactionId = (string) ($body['transactionId'] ?? sprintf('ORD-%s', bin2hex(random_bytes(4))));

    if ($username === '') {
        throw new \RuntimeException('username is required.');
    }

    $userHandle = hash('sha256', 'demo:' . $username, true);
    $credentialIds = $container->credentialStore->credentialIdsForUser($userHandle);
    if ($credentialIds === []) {
        throw new \RuntimeException('No credential registered for that user — register first.');
    }

    $challenge = random_bytes(32);
    $instrument = PaymentCredentialInstrument::create(
        displayName: 'Demo card •••• 1234',
        icon: 'https://placehold.co/64x64.png?text=Card',
    );
    $total = PaymentCurrencyAmount::create(currency: $currency, value: $amount);

    // SPC requires `payeeOrigin` to be a valid HTTPS URL — Chrome rejects
    // `http://localhost` here. The browser displays this in the SPC dialog
    // but never networks to it, so the demo origin does not need to exist.
    $payeeOrigin = 'https://demo-merchant.example';

    // `topOrigin`, in contrast, is stamped by the user agent into
    // `clientDataJSON.payment.topOrigin` and reflects the actual top-level
    // browsing context. PaymentClientDataCollector compares the input we put
    // here against that signed value, so we must echo the merchant page's
    // real Origin header (whatever it is — http://localhost:8000 in the
    // standalone demo) not the fixed demo merchant value.
    $topOrigin = is_string($_SERVER['HTTP_ORIGIN'] ?? null)
        ? $_SERVER['HTTP_ORIGIN']
        : rtrim($container->allowedOrigins[0], '/');

    // Build the SPC request options server-side and persist them so we can
    // hand the SAME values to PaymentClientDataCollector when the merchant
    // posts the assertion back. This is what closes the SPC loop: the
    // collector compares clientDataJSON.payment to these values.
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
                topOrigin: $topOrigin,
                total: $total,
                instrument: $instrument,
                payeeName: 'Demo Merchant',
                payeeOrigin: $payeeOrigin,
            ),
        ]),
    );
    $requestOptions->timeout = 60_000;

    // Stash everything keyed by base64url(challenge). The challenge is the
    // unique nonce the authenticator signs, so it is the natural binding key
    // to recover merchant-side context (transaction id, cart, etc.) when the
    // assertion comes back.
    $key = Base64UrlSafe::encodeUnpadded($challenge);
    $_SESSION['spc_options'][$key] = $container->serializer->serialize($requestOptions, 'json');
    $_SESSION['spc_user'][$key] = $userHandle;
    $_SESSION['spc_txn'][$key] = $transactionId;

    // Return the trimmed payload the merchant page will hand to PaymentRequest:
    // base64url-encoded buffers, instrument + payee + total fields, and the
    // credentialIds the user agent should match.
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

function paymentVerify(Container $container): void
{
    $body = file_get_contents('php://input') ?: '{}';
    $credential = $container->serializer->deserialize($body, PublicKeyCredential::class, 'json');
    \assert($credential instanceof PublicKeyCredential);

    $response = $credential->response;
    if (! $response instanceof AuthenticatorAssertionResponse) {
        throw new \RuntimeException('Expected an AuthenticatorAssertionResponse.');
    }

    // Locate the request options we stashed when generating the SPC payload.
    // The challenge is the binding key — it was issued for exactly one
    // transaction and signed by the authenticator, so recovering the
    // associated transactionId here is tamper-proof.
    $challengeKey = Base64UrlSafe::encodeUnpadded($response->clientDataJSON->challenge);
    $optionsJson = $_SESSION['spc_options'][$challengeKey] ?? null;
    $userHandle = $_SESSION['spc_user'][$challengeKey] ?? null;
    $transactionId = $_SESSION['spc_txn'][$challengeKey] ?? null;
    if ($optionsJson === null || $userHandle === null || $transactionId === null) {
        throw new \RuntimeException('Unknown challenge — request expired or never issued.');
    }

    $requestOptions = $container->serializer->deserialize(
        (string) $optionsJson,
        PublicKeyCredentialRequestOptions::class,
        'json',
    );
    \assert($requestOptions instanceof PublicKeyCredentialRequestOptions);

    $credentialSource = $container->credentialStore->findByCredentialId($credential->rawId);
    if ($credentialSource === null) {
        throw new \RuntimeException('Unknown credential.');
    }

    // PaymentClientDataCollector + PaymentExtensionOutputChecker run inside
    // ->check(): they verify clientDataJSON.payment matches the payment data
    // we put into the request options' `payment` extension above, and that
    // browserBoundSignature is well-formed.
    $updatedRecord = $container->assertionValidator->check(
        $credentialSource,
        $response,
        $requestOptions,
        $container->relyingPartyId,
        $userHandle,
    );
    $container->credentialStore->updateAfterAssertion($updatedRecord);

    unset(
        $_SESSION['spc_options'][$challengeKey],
        $_SESSION['spc_user'][$challengeKey],
        $_SESSION['spc_txn'][$challengeKey],
    );

    // Surface what just got verified. SPC is a *proof of authorization*,
    // not a payment. To actually move money the merchant/PSP forwards the
    // four WebAuthn artefacts below to the issuer (typically through 3DS2
    // SPC Authentication), which re-verifies the signature against the
    // public key it stored at enrollment time and confirms the cardholder
    // approved exactly this transaction → liability shift / SCA done.
    $signedPayment = $response->clientDataJSON->get('payment');

    echo json_encode([
        'verified' => true,
        'transactionId' => $transactionId,
        'clientDataType' => $response->clientDataJSON->type, // "payment.get"
        'signCount' => $updatedRecord->counter,
        'userPresent' => $response->authenticatorData->isUserPresent(),
        'userVerified' => $response->authenticatorData->isUserVerified(),
        // What the user signed (parsed). Compare client-side to what was shown
        // in the SPC dialog — they must be identical.
        'signedPayment' => $signedPayment,
        // The bundle of bytes you forward to the issuer / 3DS ACS. They form
        // the WebAuthn proof: signature is over `authenticatorData ||
        // sha256(clientDataJSON)`. The issuer holds the credential's public
        // key from enrollment and re-verifies the signature.
        'artefactsForIssuer' => [
            'credentialId' => Base64UrlSafe::encodeUnpadded($credential->rawId),
            'clientDataJSON' => Base64UrlSafe::encodeUnpadded($response->clientDataJSON->rawData),
            'authenticatorData' => Base64UrlSafe::encodeUnpadded($response->authenticatorData->authData),
            'signature' => Base64UrlSafe::encodeUnpadded($response->signature),
            'userHandle' => $response->userHandle === null
                ? null
                : Base64UrlSafe::encodeUnpadded($response->userHandle),
        ],
    ], JSON_THROW_ON_ERROR);
}
