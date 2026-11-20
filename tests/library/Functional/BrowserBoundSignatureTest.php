<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use Cose\Algorithm\Signature\ECDSA\ECSignature;
use Cose\Algorithms;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use const STR_PAD_LEFT;
use function strlen;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticationExtensions\AuthenticationExtensions;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticationExtensions\PaymentExtension;
use Webauthn\AuthenticationExtensions\PaymentExtensionOutputChecker;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\ClientDataCollector\ClientDataCollectorManager;
use Webauthn\ClientDataCollector\PaymentClientDataCollector;
use Webauthn\ClientDataCollector\WebauthnAuthenticationCollector;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentData;
use Webauthn\SecurePaymentConfirmation\CollectedClientAdditionalPaymentRegistrationData;
use Webauthn\SecurePaymentConfirmation\CollectedClientPaymentData;
use Webauthn\SecurePaymentConfirmation\PaymentCredentialInstrument;
use Webauthn\SecurePaymentConfirmation\PaymentCurrencyAmount;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Secure Payment Confirmation ceremonies built the way the W3C specification describes them: the browser-bound
 * public key in `clientDataJSON.payment.browserBoundPublicKey`, the browser-bound signature over the raw client data
 * in `clientExtensionResults.payment.browserBoundSignature.signature`. The credentials go through the serializer and
 * the validators built by {@see CeremonyStepManagerFactory}, as an application receives them.
 *
 * @see https://w3c.github.io/secure-payment-confirmation/
 *
 * @internal
 */
final class BrowserBoundSignatureTest extends AbstractTestCase
{
    private const RP_ID = 'localhost';

    private const ORIGIN = 'https://localhost';

    private const FLAGS_UP_UV = 0x05;

    private const FLAG_AT = 0x40;

    private const FLAG_ED = 0x80;

    private const USER_HANDLE = 'user-handle';

    private const CHALLENGE = 'a challenge of the relying party';

    private OpenSSLAsymmetricKey $passkey;

    private OpenSSLAsymmetricKey $browserBoundKey;

    private string $credentialId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->passkey = self::newP256Key();
        $this->browserBoundKey = self::newP256Key();
        $this->credentialId = random_bytes(16);
    }

    #[Test]
    public function aRegistrationWithAValidBrowserBoundSignatureIsAccepted(): void
    {
        $credentialRecord = $this->register(true, true);

        static::assertSame($this->credentialId, $credentialRecord->publicKeyCredentialId);
    }

    #[Test]
    public function aRegistrationWithoutBrowserBoundKeyIsAccepted(): void
    {
        $credentialRecord = $this->register(false, false);

        static::assertSame($this->credentialId, $credentialRecord->publicKeyCredentialId);
    }

    #[Test]
    public function aRegistrationWhoseBrowserBoundSignatureWasMadeWithAnotherKeyIsRejected(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('browserBoundSignature verification failed');

        $this->register(true, true, self::newP256Key());
    }

    #[Test]
    public function aRegistrationWithABrowserBoundPublicKeyButNoSignatureIsRejected(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('the browser-bound signature is missing');

        $this->register(true, false);
    }

    #[Test]
    public function aRegistrationWithABrowserBoundSignatureButNoPublicKeyIsRejected(): void
    {
        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('the client data carries no browser-bound public key');

        $this->register(false, true);
    }

    #[Test]
    public function aRegistrationWhosePaymentMemberIsNotAnObjectCarriesNoBrowserBoundKey(): void
    {
        $credentialRecord = $this->checkRegistration(
            $this->withRegistrationPayment($this->registration(false, false), 'not an object', false)
        );

        static::assertSame($this->credentialId, $credentialRecord->publicKeyCredentialId);
    }

    #[Test]
    public function aRegistrationWhoseBrowserBoundPublicKeyIsNotAStringIsRejected(): void
    {
        $credential = $this->withRegistrationPayment($this->registration(false, false), [
            'browserBoundPublicKey' => [
                'publicKey' => Base64UrlSafe::encodeUnpadded(self::coseKey($this->browserBoundKey)),
                'algorithm' => Algorithms::COSE_ALGORITHM_ES256,
            ],
        ], true);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid browser-bound public key: expected a non-empty base64url string.');

        $this->checkRegistration($credential);
    }

    #[Test]
    public function aRegistrationWhoseBrowserBoundPublicKeyIsEmptyIsRejected(): void
    {
        $credential = $this->withRegistrationPayment($this->registration(false, false), [
            'browserBoundPublicKey' => '',
        ], true);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid browser-bound public key: expected a non-empty base64url string.');

        $this->checkRegistration($credential);
    }

    #[Test]
    public function aRegistrationWithAPaddedBrowserBoundPublicKeyIsAccepted(): void
    {
        $credential = $this->withRegistrationPayment($this->registration(false, false), [
            'browserBoundPublicKey' => Base64UrlSafe::encode(self::coseKey($this->browserBoundKey)),
        ], true);

        $credentialRecord = $this->checkRegistration($credential);

        static::assertSame($this->credentialId, $credentialRecord->publicKeyCredentialId);
    }

    #[Test]
    public function aRegistrationWhoseBrowserBoundPublicKeyHasNoAlgorithmIsRejected(): void
    {
        $credential = $this->withRegistrationPayment($this->registration(false, false), [
            'browserBoundPublicKey' => Base64UrlSafe::encodeUnpadded(self::coseKey($this->browserBoundKey, false)),
        ], true);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('the COSE_Key has no integer "alg" member');

        $this->checkRegistration($credential);
    }

    #[Test]
    public function theApplicationReadsTheBrowserBoundPublicKeyOfARegistration(): void
    {
        $credential = $this->registration(true, true);
        $this->checkRegistration($credential);

        $paymentData = $this->getSerializer()
            ->denormalize(
                $this->deserialize($credential)
                    ->response->clientDataJSON->data,
                CollectedClientPaymentData::class
            );

        static::assertInstanceOf(CollectedClientAdditionalPaymentRegistrationData::class, $paymentData->payment);
        static::assertNotNull($paymentData->payment->browserBoundPublicKey);
        static::assertSame(
            self::coseKey($this->browserBoundKey),
            $paymentData->payment->browserBoundPublicKey->publicKey
        );
        static::assertSame(
            Algorithms::COSE_ALGORITHM_ES256,
            $paymentData->payment->browserBoundPublicKey->algorithm()
        );
    }

    #[Test]
    public function theApplicationReadsTheSameBrowserBoundPublicKeyAtAuthentication(): void
    {
        $registration = $this->registration(true, true);
        $this->checkRegistration($registration);
        $payment = $this->payment(true, null);
        $this->checkPayment($payment);

        $registrationData = $this->getSerializer()
            ->denormalize(
                $this->deserialize($registration)
                    ->response->clientDataJSON->data,
                CollectedClientPaymentData::class
            );
        $paymentData = $this->getSerializer()
            ->denormalize(
                $this->deserialize($payment)
                    ->response->clientDataJSON->data,
                CollectedClientPaymentData::class
            );

        static::assertInstanceOf(CollectedClientAdditionalPaymentData::class, $paymentData->payment);
        static::assertNotNull($paymentData->payment->browserBoundPublicKey);
        static::assertSame(
            Algorithms::COSE_ALGORITHM_ES256,
            $paymentData->payment->browserBoundPublicKey->algorithm()
        );
        static::assertEquals(
            $registrationData->payment->browserBoundPublicKey,
            $paymentData->payment->browserBoundPublicKey
        );
    }

    #[Test]
    public function aPaymentWithAValidBrowserBoundSignatureIsAccepted(): void
    {
        $credentialRecord = $this->checkPayment($this->payment(true, null));

        static::assertSame(1, $credentialRecord->counter);
    }

    #[Test]
    public function aBrowserBoundSignatureInTheRawCoseFormIsAccepted(): void
    {
        $credentialRecord = $this->checkPayment($this->payment(true, null, true));

        static::assertSame(1, $credentialRecord->counter);
    }

    #[Test]
    public function aPaymentWithoutBrowserBoundKeyIsAccepted(): void
    {
        $credentialRecord = $this->checkPayment($this->payment(false, null));

        static::assertSame(1, $credentialRecord->counter);
    }

    #[Test]
    public function aPaymentWhoseBrowserBoundSignatureWasMadeWithAnotherKeyIsRejected(): void
    {
        $credential = $this->payment(true, null, false, self::newP256Key());

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('browserBoundSignature verification failed');

        $this->checkPayment($credential);
    }

    #[Test]
    public function aPaymentWhoseClientExtensionResultsWereNotSentIsRejected(): void
    {
        $credential = $this->payment(true, null);
        unset($credential['clientExtensionResults']);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('the browser-bound signature is missing from the client extension results');

        $this->checkPayment($credential);
    }

    #[Test]
    public function aBrowserBoundSignatureWithoutBrowserBoundPublicKeyIsRejected(): void
    {
        $credential = $this->payment(false, $this->signatureEntry());

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('the client data carries no browser-bound public key');

        $this->checkPayment($credential);
    }

    #[Test]
    public function aBrowserBoundPublicKeyThatIsNotAStringIsRejected(): void
    {
        $credential = $this->payment(true, null);
        $clientData = json_decode(
            Base64UrlSafe::decodeNoPadding($credential['response']['clientDataJSON']),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $clientData['payment']['browserBoundPublicKey'] = [
            'publicKey' => $clientData['payment']['browserBoundPublicKey'],
            'algorithm' => -7,
        ];
        $credential['response']['clientDataJSON'] = Base64UrlSafe::encodeUnpadded(
            json_encode($clientData, JSON_THROW_ON_ERROR)
        );

        $this->expectException(InvalidDataException::class);
        $this->expectExceptionMessage('Invalid browserBoundPublicKey');

        $this->checkPayment($credential);
    }

    #[Test]
    public function aBrowserBoundSignatureThatIsNotABase64UrlStringIsRejected(): void
    {
        $credential = $this->payment(true, []);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid browser-bound signature: expected a non-empty base64url string.');

        $this->checkPayment($credential);
    }

    #[Test]
    public function aBrowserBoundSignatureThatDecodesToNothingIsRejected(): void
    {
        $credential = $this->payment(true, [
            'signature' => '=',
        ]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid browser-bound signature: expected a non-empty base64url string.');

        $this->checkPayment($credential);
    }

    #[Test]
    public function aPaymentOutputThatIsNotAnObjectIsRejected(): void
    {
        $credential = $this->payment(true, null);
        $credential['clientExtensionResults']['payment'] = 'not an object';

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid payment extension output: expected an object.');

        $this->checkPayment($credential);
    }

    #[Test]
    public function aBrowserBoundSignatureMemberThatIsNotAnObjectIsRejected(): void
    {
        $credential = $this->payment(true, null);
        $credential['clientExtensionResults']['payment']['browserBoundSignature'] = 'not an object';

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('"browserBoundSignature" must be an object.');

        $this->checkPayment($credential);
    }

    #[Test]
    public function anotherAuthenticatorExtensionNextToThePaymentIsAccepted(): void
    {
        $credential = $this->payment(true, null, false, null, [
            MapItem::create(TextStringObject::create('credProtect'), UnsignedIntegerObject::create(2)),
        ]);

        $credentialRecord = $this->checkPayment($credential);

        static::assertSame(1, $credentialRecord->counter);
    }

    #[Test]
    public function aPaymentEntryInTheAuthenticatorDataIsRejected(): void
    {
        $credential = $this->payment(true, null, false, null, [
            MapItem::create(TextStringObject::create('payment'), UnsignedIntegerObject::create(1)),
        ]);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('must not contain a "payment" entry');

        $this->checkPayment($credential);
    }

    #[Test]
    public function theClientExtensionResultsAreAttachedToTheResponse(): void
    {
        $credential = $this->deserialize($this->payment(true, null));

        static::assertNotNull($credential->response->clientExtensionResults);
        static::assertTrue($credential->response->clientExtensionResults->has('payment'));
    }

    #[Test]
    public function clientExtensionResultsThatAreNotAMapAreIgnored(): void
    {
        $data = $this->payment(false, null);
        $data['clientExtensionResults'] = ['not', 'a', 'map'];

        $credential = $this->deserialize($data);

        static::assertNull($credential->response->clientExtensionResults);
        $this->checkPayment($data);
    }

    #[Test]
    public function anAssertionWithoutPaymentExtensionIgnoresThePaymentOutput(): void
    {
        $response = $this->deserialize($this->payment(true, null, false, self::newP256Key(), [], false))
            ->response;
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);
        $options = PublicKeyCredentialRequestOptions::create(
            self::CHALLENGE,
            self::RP_ID,
            [PublicKeyCredentialDescriptor::create('public-key', $this->credentialId)],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        );

        $credentialRecord = $this->assertionValidator()
            ->check($this->credentialRecord(), $response, $options, self::RP_ID, self::USER_HANDLE);

        static::assertSame(1, $credentialRecord->counter);
    }

    private function register(
        bool $withPublicKey,
        bool $withSignature,
        null|OpenSSLAsymmetricKey $signingKey = null
    ): CredentialRecord {
        return $this->checkRegistration($this->registration($withPublicKey, $withSignature, $signingKey));
    }

    /**
     * The JSON a browser posts after a registration made with the `payment` extension.
     *
     * @return array<string, mixed>
     */
    private function registration(
        bool $withPublicKey,
        bool $withSignature,
        null|OpenSSLAsymmetricKey $signingKey = null
    ): array {
        $payment = $withPublicKey ? [
            'browserBoundPublicKey' => Base64UrlSafe::encodeUnpadded(self::coseKey($this->browserBoundKey)),
        ] : [];
        $clientDataJSON = json_encode([
            'type' => 'webauthn.create',
            'challenge' => Base64UrlSafe::encodeUnpadded(self::CHALLENGE),
            'origin' => self::ORIGIN,
            'payment' => $payment,
        ], JSON_THROW_ON_ERROR);
        $authData = hash('sha256', self::RP_ID, true)
            . chr(self::FLAGS_UP_UV | self::FLAG_AT)
            . pack('N', 0)
            . str_repeat("\0", 16)
            . pack('n', strlen($this->credentialId)) . $this->credentialId
            . self::coseKey($this->passkey);
        $attestationObject = MapObject::create([
            MapItem::create(TextStringObject::create('fmt'), TextStringObject::create('none')),
            MapItem::create(TextStringObject::create('attStmt'), MapObject::create()),
            MapItem::create(TextStringObject::create('authData'), ByteStringObject::create($authData)),
        ]);

        return [
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJSON),
                'attestationObject' => Base64UrlSafe::encodeUnpadded((string) $attestationObject),
            ],
            'clientExtensionResults' => [
                'payment' => $withSignature ? [
                    'browserBoundSignature' => [
                        'signature' => Base64UrlSafe::encodeUnpadded(
                            self::sign($clientDataJSON, $signingKey ?? $this->browserBoundKey)
                        ),
                    ],
                ] : [],
            ],
        ];
    }

    /**
     * Replaces the `payment` member of the client data of a registration. With the "none" attestation, the
     * authenticator signs nothing that depends on the client data, so only the browser-bound signature is made again,
     * when $withSignature is true.
     *
     * @param array<string, mixed> $credential
     *
     * @return array<string, mixed>
     */
    private function withRegistrationPayment(array $credential, mixed $payment, bool $withSignature): array
    {
        $clientData = json_decode(
            Base64UrlSafe::decodeNoPadding($credential['response']['clientDataJSON']),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $clientData['payment'] = $payment;
        $clientDataJSON = json_encode($clientData, JSON_THROW_ON_ERROR);
        $credential['response']['clientDataJSON'] = Base64UrlSafe::encodeUnpadded($clientDataJSON);
        $credential['clientExtensionResults']['payment'] = $withSignature ? [
            'browserBoundSignature' => [
                'signature' => Base64UrlSafe::encodeUnpadded(self::sign($clientDataJSON, $this->browserBoundKey)),
            ],
        ] : [];

        return $credential;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function checkRegistration(array $data): CredentialRecord
    {
        $response = $this->deserialize($data)
            ->response;
        static::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Bank', self::RP_ID),
            PublicKeyCredentialUserEntity::create('john', self::USER_HANDLE, 'John'),
            self::CHALLENGE,
            [PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256)],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            [],
            null,
            AuthenticationExtensions::create([PaymentExtension::register()]),
        );

        return AuthenticatorAttestationResponseValidator::create($this->ceremonyStepManagerFactory()->creationCeremony())
            ->check($response, $options, self::RP_ID);
    }

    /**
     * The JSON a browser posts after a Secure Payment Confirmation authentication.
     *
     * @param array<string, mixed>|null $signatureEntry The `browserBoundSignature` member sent as it is; when null, a
     *                                                  signature over the client data is computed unless $withPublicKey is false
     * @param MapItem[] $authenticatorExtensions
     * @param bool $securePaymentConfirmation When false, a plain WebAuthn assertion: `webauthn.get`, no payment data
     *
     * @return array<string, mixed>
     */
    private function payment(
        bool $withPublicKey,
        null|array $signatureEntry,
        bool $rawSignature = false,
        null|OpenSSLAsymmetricKey $signingKey = null,
        array $authenticatorExtensions = [],
        bool $securePaymentConfirmation = true
    ): array {
        $payment = [
            'rpId' => self::RP_ID,
            'topOrigin' => self::ORIGIN,
            'total' => [
                'currency' => 'EUR',
                'value' => '10.00',
            ],
            'instrument' => [
                'displayName' => 'Card',
                'icon' => 'https://localhost/card.png',
            ],
        ];
        if ($withPublicKey) {
            $payment['browserBoundPublicKey'] = Base64UrlSafe::encodeUnpadded(self::coseKey($this->browserBoundKey));
        }
        $clientData = [
            'type' => 'webauthn.get',
            'challenge' => Base64UrlSafe::encodeUnpadded(self::CHALLENGE),
            'origin' => self::ORIGIN,
        ];
        if ($securePaymentConfirmation) {
            $clientData['type'] = 'payment.get';
            $clientData['payment'] = $payment;
        }
        $clientDataJSON = json_encode($clientData, JSON_THROW_ON_ERROR);

        $flags = self::FLAGS_UP_UV;
        $extensions = '';
        if ($authenticatorExtensions !== []) {
            $flags |= self::FLAG_ED;
            $extensions = (string) MapObject::create($authenticatorExtensions);
        }
        $authenticatorData = hash('sha256', self::RP_ID, true) . chr($flags) . pack('N', 1) . $extensions;

        if ($signatureEntry === null && $withPublicKey) {
            $signature = self::sign($clientDataJSON, $signingKey ?? $this->browserBoundKey);
            if ($rawSignature) {
                $signature = ECSignature::fromAsn1($signature, 64);
            }
            $signatureEntry = [
                'signature' => Base64UrlSafe::encodeUnpadded($signature),
            ];
        }
        $paymentOutput = $signatureEntry === null ? [] : [
            'browserBoundSignature' => $signatureEntry,
        ];

        return [
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientDataJSON),
                'authenticatorData' => Base64UrlSafe::encodeUnpadded($authenticatorData),
                'signature' => Base64UrlSafe::encodeUnpadded(
                    self::sign($authenticatorData . hash('sha256', $clientDataJSON, true), $this->passkey)
                ),
                'userHandle' => Base64UrlSafe::encodeUnpadded(self::USER_HANDLE),
            ],
            'clientExtensionResults' => [
                'payment' => $paymentOutput,
            ],
        ];
    }

    /**
     * @return array{signature: string}
     */
    private function signatureEntry(): array
    {
        return [
            'signature' => Base64UrlSafe::encodeUnpadded(self::sign('another client data', $this->browserBoundKey)),
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function checkPayment(array $data): CredentialRecord
    {
        $response = $this->deserialize($data)
            ->response;
        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);
        $options = PublicKeyCredentialRequestOptions::create(
            self::CHALLENGE,
            self::RP_ID,
            [PublicKeyCredentialDescriptor::create('public-key', $this->credentialId)],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            null,
            AuthenticationExtensions::create([
                PaymentExtension::authenticate(
                    self::RP_ID,
                    self::ORIGIN,
                    PaymentCurrencyAmount::create('EUR', '10.00'),
                    PaymentCredentialInstrument::create('Card', 'https://localhost/card.png'),
                ),
            ]),
        );

        return $this->assertionValidator()
            ->check($this->credentialRecord(), $response, $options, self::RP_ID, self::USER_HANDLE);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function deserialize(array $data): PublicKeyCredential
    {
        return $this->getSerializer()
            ->deserialize(json_encode($data, JSON_THROW_ON_ERROR), PublicKeyCredential::class, 'json');
    }

    private function assertionValidator(): AuthenticatorAssertionResponseValidator
    {
        return AuthenticatorAssertionResponseValidator::create($this->ceremonyStepManagerFactory()->requestCeremony());
    }

    private function ceremonyStepManagerFactory(): CeremonyStepManagerFactory
    {
        $extensionOutputCheckerHandler = ExtensionOutputCheckerHandler::create();
        $extensionOutputCheckerHandler->add(new PaymentExtensionOutputChecker());

        $factory = new CeremonyStepManagerFactory();
        $factory->setExtensionOutputCheckerHandler($extensionOutputCheckerHandler);
        $factory->setClientDataCollectorManager(new ClientDataCollectorManager([
            new WebauthnAuthenticationCollector(),
            new PaymentClientDataCollector($this->getSerializer()),
        ]));

        return $factory;
    }

    private function credentialRecord(): CredentialRecord
    {
        return CredentialRecord::create(
            $this->credentialId,
            'public-key',
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            self::coseKey($this->passkey),
            self::USER_HANDLE,
            0,
        );
    }

    private static function newP256Key(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $key);

        return $key;
    }

    /**
     * @return string DER, as the platform key stores produce it
     */
    private static function sign(string $data, OpenSSLAsymmetricKey $key): string
    {
        $signature = '';
        openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);

        return $signature;
    }

    private static function coseKey(OpenSSLAsymmetricKey $key, bool $withAlgorithm = true): string
    {
        $details = openssl_pkey_get_details($key);
        static::assertIsArray($details);

        $items = [
            MapItem::create(UnsignedIntegerObject::create(Key::TYPE), UnsignedIntegerObject::create(Key::TYPE_EC2)),
        ];
        if ($withAlgorithm) {
            $items[] = MapItem::create(
                UnsignedIntegerObject::create(Key::ALG),
                NegativeIntegerObject::create(Algorithms::COSE_ALGORITHM_ES256)
            );
        }
        $items[] = MapItem::create(
            NegativeIntegerObject::create(Ec2Key::DATA_CURVE),
            UnsignedIntegerObject::create(Ec2Key::CURVE_P256)
        );
        $items[] = MapItem::create(
            NegativeIntegerObject::create(Ec2Key::DATA_X),
            ByteStringObject::create(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT))
        );
        $items[] = MapItem::create(
            NegativeIntegerObject::create(Ec2Key::DATA_Y),
            ByteStringObject::create(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT))
        );

        return (string) MapObject::create($items);
    }
}
