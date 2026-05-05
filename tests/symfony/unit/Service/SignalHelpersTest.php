<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Service;

use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorResponse;
use Webauthn\Bundle\Repository\CredentialRecordRepositoryInterface;
use Webauthn\Bundle\Security\Authentication\Exception\WebauthnAuthenticationFailureException;
use Webauthn\Bundle\Service\WebauthnSignalFactory;
use Webauthn\Bundle\Service\WebauthnSignalResponse;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Signal\Signal;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * @internal
 */
final class SignalHelpersTest extends TestCase
{
    #[Test]
    public function unknownCredentialSignalProducesTheW3CDictionaryShape(): void
    {
        $factory = new WebauthnSignalFactory($this->emptyRepository());

        $signal = $factory->forUnknownCredential(
            'example.com',
            PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                'rawCredentialIdBytes',
            ),
        );

        $payload = $this->envelope($signal);
        static::assertSame([
            [
                'type' => 'unknownCredential',
                'options' => [
                    'rpId' => 'example.com',
                    'credentialId' => Base64UrlSafe::encodeUnpadded('rawCredentialIdBytes'),
                ],
            ],
        ], $payload['signals']);
    }

    #[Test]
    public function unknownCredentialFromExceptionExtractsTheDescriptorFromTheCarriedCredential(): void
    {
        $factory = new WebauthnSignalFactory($this->emptyRepository());
        $credential = new PublicKeyCredential(
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            'rawCredentialIdBytes',
            static::createStub(AuthenticatorResponse::class),
        );
        $exception = new WebauthnAuthenticationFailureException(
            'Credential ID is invalid.',
            publicKeyCredential: $credential,
        );

        $signal = $factory->forUnknownCredentialFromException('example.com', $exception);

        static::assertNotNull($signal);
        static::assertSame('example.com', $signal->rp->id);
        static::assertSame('rawCredentialIdBytes', $signal->credential->id);
    }

    #[Test]
    public function unknownCredentialFromExceptionReturnsNullWhenNoCredentialIsCarried(): void
    {
        $factory = new WebauthnSignalFactory($this->emptyRepository());
        $exception = new WebauthnAuthenticationFailureException('Credential ID is invalid.');

        static::assertNull($factory->forUnknownCredentialFromException('example.com', $exception));
    }

    #[Test]
    public function allAcceptedCredentialsListIsDerivedExhaustivelyFromTheRepository(): void
    {
        $user = PublicKeyCredentialUserEntity::create(
            name: 'alice',
            id: 'user-handle-bytes',
            displayName: 'Alice',
        );
        $factory = new WebauthnSignalFactory($this->repositoryWith([
            $this->record('cred-A'),
            $this->record('cred-B'),
        ]));

        $signal = $factory->forAllAccepted('example.com', $user);

        $payload = $this->envelope($signal);
        static::assertCount(1, $payload['signals']);
        static::assertSame('allAcceptedCredentials', $payload['signals'][0]['type']);

        $options = $payload['signals'][0]['options'];
        static::assertSame('example.com', $options['rpId']);
        static::assertSame(Base64UrlSafe::encodeUnpadded('user-handle-bytes'), $options['userId']);
        static::assertSame(
            [Base64UrlSafe::encodeUnpadded('cred-A'), Base64UrlSafe::encodeUnpadded('cred-B')],
            $options['allAcceptedCredentialIds'],
        );
    }

    #[Test]
    public function currentUserDetailsCarriesNameAndDisplayName(): void
    {
        $factory = new WebauthnSignalFactory($this->emptyRepository());
        $user = PublicKeyCredentialUserEntity::create(
            name: 'alice@example.com',
            id: 'user-handle-bytes',
            displayName: 'Alice Liddell',
        );

        $signal = $factory->forCurrentUser('example.com', $user);

        static::assertSame([
            [
                'type' => 'currentUserDetails',
                'options' => [
                    'rpId' => 'example.com',
                    'userId' => Base64UrlSafe::encodeUnpadded('user-handle-bytes'),
                    'name' => 'alice@example.com',
                    'displayName' => 'Alice Liddell',
                ],
            ],
        ], $this->envelope($signal)['signals']);
    }

    #[Test]
    public function withSignalsTagsEachSignalWithItsDispatchTypeAndPreservesTheApplicationPayload(): void
    {
        $user = PublicKeyCredentialUserEntity::create(name: 'alice', id: 'h', displayName: 'Alice');
        $factory = new WebauthnSignalFactory($this->emptyRepository());
        $response = new WebauthnSignalResponse($this->serializer());

        $jsonResponse = $response->withSignals(
            [
                'success' => true,
                'next' => '/dashboard',
            ],
            $factory->forAllAccepted('example.com', $user),
            $factory->forCurrentUser('example.com', $user),
        );

        $payload = $this->decode($jsonResponse);
        static::assertTrue($payload['success']);
        static::assertSame('/dashboard', $payload['next']);
        static::assertSame(
            ['allAcceptedCredentials', 'currentUserDetails'],
            array_column($payload['signals'], 'type'),
        );
    }

    private function record(string $credentialId): CredentialRecord
    {
        return new CredentialRecord(
            publicKeyCredentialId: $credentialId,
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            transports: [],
            attestationType: AttestationStatement::TYPE_NONE,
            trustPath: EmptyTrustPath::create(),
            aaguid: Uuid::fromBinary(str_repeat("\0", 16)),
            credentialPublicKey: 'pub-key',
            userHandle: 'user-handle-bytes',
            counter: 0,
        );
    }

    private function emptyRepository(): CredentialRecordRepositoryInterface
    {
        return $this->repositoryWith([]);
    }

    /**
     * @param list<CredentialRecord> $records
     */
    private function repositoryWith(array $records): CredentialRecordRepositoryInterface
    {
        return new class($records) implements CredentialRecordRepositoryInterface {
            /**
             * @param list<CredentialRecord> $records
             */
            public function __construct(
                private readonly array $records
            ) {
            }

            public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
            {
                foreach ($this->records as $record) {
                    if ($record->publicKeyCredentialId === $publicKeyCredentialId) {
                        return $record;
                    }
                }

                return null;
            }

            /**
             * @return array<CredentialRecord>
             */
            public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
            {
                return array_values(array_filter(
                    $this->records,
                    static fn (CredentialRecord $r): bool => $r->userHandle === $publicKeyCredentialUserEntity->id,
                ));
            }
        };
    }

    private function serializer(): Serializer
    {
        $manager = AttestationStatementSupportManager::create();
        $manager->add(NoneAttestationStatementSupport::create());

        return (new WebauthnSerializerFactory($manager))->create();
    }

    /**
     * @return array{signals: list<array{type: string, options: array<string, mixed>}>, success?: bool, next?: string}
     */
    private function envelope(Signal $signal): array
    {
        return $this->decode((new WebauthnSignalResponse($this->serializer()))->withSignals([], $signal));
    }

    /**
     * @return array{signals: list<array{type: string, options: array<string, mixed>}>, success?: bool, next?: string}
     */
    private function decode(JsonResponse $response): array
    {
        return json_decode($response->getContent() ?: '', true, flags: JSON_THROW_ON_ERROR);
    }
}
