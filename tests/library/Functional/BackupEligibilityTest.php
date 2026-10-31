<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use function chr;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use const STR_PAD_LEFT;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorData;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Event\AuthenticatorAssertionResponseValidationFailedEvent;
use Webauthn\Event\BackupEligibilityChangedEvent;
use Webauthn\Event\BackupStatusChangedEvent;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\AbstractTestCase;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Issue #969: the BE flag recorded for a credential is permanent, an assertion can neither rewrite it nor be accepted
 * with another value. The assertions are signed on the fly with a P-256 key generated for each test, so that the same
 * credential can claim other flags from one ceremony to the next.
 *
 * @internal
 */
final class BackupEligibilityTest extends AbstractTestCase
{
    private const CREDENTIAL_ID = 'credential-id';

    private const USER_HANDLE = 'user-handle';

    private const CHALLENGE = 'challenge-of-the-authentication-ceremony';

    private OpenSSLAsymmetricKey $privateKey;

    private string $credentialPublicKey;

    /**
     * @var object[]
     */
    private array $dispatchedEvents = [];

    protected function setUp(): void
    {
        parent::setUp();

        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey);
        $details = openssl_pkey_get_details($privateKey);
        static::assertIsArray($details);
        /** @var array{ec: array{x: string, y: string}} $details */
        $this->privateKey = $privateKey;
        $this->credentialPublicKey = (string) MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(
                NegativeIntegerObject::create(-2),
                ByteStringObject::create(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT))
            )
            ->add(
                NegativeIntegerObject::create(-3),
                ByteStringObject::create(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT))
            );
    }

    #[Test]
    public function anAssertionCannotChangeTheBackupEligibilityRecordedAtRegistration(): void
    {
        $credentialRecord = $this->credentialRecord(true, true);
        $validator = $this->validator();
        $validator->check(
            $credentialRecord,
            $this->assertion(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE | AuthenticatorData::FLAG_BS, 1),
            $this->requestOptions(),
            'localhost',
            self::USER_HANDLE
        );

        try {
            $validator->check(
                $credentialRecord,
                $this->assertion(AuthenticatorData::FLAG_UP, 2),
                $this->requestOptions(),
                'localhost',
                self::USER_HANDLE
            );
            static::fail('An assertion that clears the BE flag of a multi-device credential must be rejected.');
        } catch (AuthenticatorResponseVerificationException $exception) {
            static::assertSame(
                'The backup eligibility flag does not match the value recorded for the credential.',
                $exception->getMessage()
            );
        }

        static::assertTrue($credentialRecord->backupEligible);
        static::assertTrue($credentialRecord->backupStatus);
        static::assertSame(1, $credentialRecord->counter);
        static::assertSame([], $this->eventsOf(BackupEligibilityChangedEvent::class));
        static::assertCount(1, $this->eventsOf(AuthenticatorAssertionResponseValidationFailedEvent::class));
    }

    #[Test]
    public function theBackupStateStillFollowsTheAssertions(): void
    {
        $credentialRecord = $this->credentialRecord(true, true);

        $this->validator()
            ->check(
                $credentialRecord,
                $this->assertion(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE, 1),
                $this->requestOptions(),
                'localhost',
                self::USER_HANDLE
            );

        static::assertTrue($credentialRecord->backupEligible);
        static::assertFalse($credentialRecord->backupStatus);
        static::assertSame([], $this->eventsOf(BackupEligibilityChangedEvent::class));
        $backupStatusEvents = $this->eventsOf(BackupStatusChangedEvent::class);
        static::assertCount(1, $backupStatusEvents);
        static::assertTrue($backupStatusEvents[0]->previousValue);
        static::assertFalse($backupStatusEvents[0]->newValue);
    }

    #[Test]
    public function aCeremonyWithoutTheComparisonStillDoesNotRewriteTheRecordedBackupEligibility(): void
    {
        $credentialRecord = $this->credentialRecord(true, true);

        AuthenticatorAssertionResponseValidator::create(new CeremonyStepManager([]))->check(
            $credentialRecord,
            $this->assertion(AuthenticatorData::FLAG_UP, 1),
            $this->requestOptions(),
            'localhost',
            self::USER_HANDLE
        );

        static::assertTrue($credentialRecord->backupEligible);
        static::assertFalse($credentialRecord->backupStatus);
    }

    #[Test]
    public function aCredentialRecordWithoutBackupEligibilityRecordsTheOneOfItsFirstAssertion(): void
    {
        $credentialRecord = $this->credentialRecord(null, null);
        $validator = $this->validator();
        $validator->check(
            $credentialRecord,
            $this->assertion(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE | AuthenticatorData::FLAG_BS, 1),
            $this->requestOptions(),
            'localhost',
            self::USER_HANDLE
        );

        static::assertTrue($credentialRecord->backupEligible);
        $backupEligibilityEvents = $this->eventsOf(BackupEligibilityChangedEvent::class);
        static::assertCount(1, $backupEligibilityEvents);
        static::assertNull($backupEligibilityEvents[0]->previousValue);
        static::assertTrue($backupEligibilityEvents[0]->newValue);

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage(
            'The backup eligibility flag does not match the value recorded for the credential.'
        );
        $validator->check(
            $credentialRecord,
            $this->assertion(AuthenticatorData::FLAG_UP, 2),
            $this->requestOptions(),
            'localhost',
            self::USER_HANDLE
        );
    }

    #[Test]
    public function aForgedAssertionIsRejectedForItsSignatureBeforeItsBackupEligibilityIsCompared(): void
    {
        $credentialRecord = $this->credentialRecord(true, true);
        $genuineAssertion = $this->assertion(AuthenticatorData::FLAG_UP, 1);
        $forgedAssertion = AuthenticatorAssertionResponse::create(
            $genuineAssertion->clientDataJSON,
            $genuineAssertion->authenticatorData,
            $this->assertion(AuthenticatorData::FLAG_UP | AuthenticatorData::FLAG_BE, 1)->signature
        );

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $this->expectExceptionMessage('Invalid signature.');
        $this->validator()
            ->check($credentialRecord, $forgedAssertion, $this->requestOptions(), 'localhost', self::USER_HANDLE);
    }

    private function validator(): AuthenticatorAssertionResponseValidator
    {
        $validator = $this->getAuthenticatorAssertionResponseValidator();
        $validator->setEventDispatcher(new class($this->dispatchedEvents) implements EventDispatcherInterface {
            /**
             * @param object[] $events
             */
            public function __construct(
                private array &$events
            ) {
            }

            public function dispatch(object $event): object
            {
                $this->events[] = $event;

                return $event;
            }
        });

        return $validator;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return list<T>
     */
    private function eventsOf(string $class): array
    {
        return array_values(
            array_filter($this->dispatchedEvents, static fn (object $event): bool => $event instanceof $class)
        );
    }

    private function credentialRecord(?bool $backupEligible, ?bool $backupStatus): CredentialRecord
    {
        return CredentialRecord::create(
            self::CREDENTIAL_ID,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            $this->credentialPublicKey,
            self::USER_HANDLE,
            0,
            null,
            $backupEligible,
            $backupStatus
        );
    }

    private function requestOptions(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create(
            self::CHALLENGE,
            'localhost',
            [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    self::CREDENTIAL_ID
                ),
            ],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        );
    }

    private function assertion(int $flags, int $signCount): AuthenticatorAssertionResponse
    {
        $clientData = [
            'type' => 'webauthn.get',
            'challenge' => Base64UrlSafe::encodeUnpadded(self::CHALLENGE),
            'origin' => 'https://localhost',
        ];
        $rawClientData = json_encode($clientData, JSON_THROW_ON_ERROR);
        $rpIdHash = hash('sha256', 'localhost', true);
        $rawAuthenticatorData = $rpIdHash . chr($flags) . pack('N', $signCount);
        openssl_sign(
            $rawAuthenticatorData . hash('sha256', $rawClientData, true),
            $signature,
            $this->privateKey,
            OPENSSL_ALGO_SHA256
        );

        return AuthenticatorAssertionResponse::create(
            CollectedClientData::create($rawClientData, $clientData),
            AuthenticatorData::create($rawAuthenticatorData, $rpIdHash, chr($flags), $signCount),
            $signature
        );
    }
}
