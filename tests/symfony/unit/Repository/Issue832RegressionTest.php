<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Repository;

use Doctrine\Persistence\ManagerRegistry;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\Bundle\Repository\DoctrineCredentialSourceRepository;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Issue #832: subclasses of DoctrineCredentialSourceRepository overriding
 * saveCredentialSource(PublicKeyCredentialSource) (5.2.x style) must keep compiling
 * AND must still be invoked when the bundle saves a credential.
 *
 * @internal
 */
final class Issue832RegressionTest extends TestCase
{
    #[Test]
    public function legacySubclassWithOldSignatureCompiles(): void
    {
        // Just loading the class body would have crashed in vanilla 5.3.x with:
        //   Compile Error: Declaration of [...]::saveCredentialSource(PublicKeyCredentialSource)
        //   must be compatible with [...]::saveCredentialSource(CredentialRecord)
        $reflection = new ReflectionMethod(LegacyDoctrineRepositoryFixture::class, 'saveCredentialSource');
        $parameters = $reflection->getParameters();

        static::assertCount(1, $parameters);
        $type = $parameters[0]->getType();
        static::assertInstanceOf(ReflectionNamedType::class, $type);
        static::assertSame(PublicKeyCredentialSource::class, $type->getName());
    }

    #[Test]
    public function newSaveDispatchesToLegacyOverrideWhenInstanceIsPublicKeyCredentialSource(): void
    {
        // saveCredentialRecord() must route PublicKeyCredentialSource arguments through
        // saveCredentialSource() so that a 5.2.x subclass override is honored.
        $repository = (new ReflectionClass(LegacyDoctrineRepositoryFixture::class))
            ->newInstanceWithoutConstructor();

        $pkcs = new PublicKeyCredentialSource(
            'pkcs-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        $repository->saveCredentialRecord($pkcs);

        static::assertSame([$pkcs], $repository->savedViaLegacyMethod);
    }

    #[Test]
    public function newSaveBypassesLegacyOverrideForBareCredentialRecord(): void
    {
        // A raw CredentialRecord (not a PublicKeyCredentialSource) cannot be passed to the legacy
        // method (parameter is typed as PublicKeyCredentialSource), so the parent must persist directly.
        // Persistence requires a real Doctrine EntityManager, which we don't bootstrap here, so we
        // simply assert that the legacy override path is NOT taken.
        $repository = (new ReflectionClass(LegacyDoctrineRepositoryFixture::class))
            ->newInstanceWithoutConstructor();

        $credentialRecord = CredentialRecord::create(
            'cr-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'public-key',
            'user-handle',
            10
        );

        try {
            $repository->saveCredentialRecord($credentialRecord);
        } catch (Throwable) {
            // Expected: persistCredentialRecord() requires an EntityManager we did not wire.
            // The important assertion is that the legacy method was not invoked.
        }

        static::assertSame([], $repository->savedViaLegacyMethod);
    }
}

/**
 * Mimics user code documented for v5.0/5.1/5.2: extends the deprecated
 * DoctrineCredentialSourceRepository and keeps the legacy save signature.
 *
 * @internal
 *
 * @extends DoctrineCredentialSourceRepository<PublicKeyCredentialSource>
 */
final class LegacyDoctrineRepositoryFixture extends DoctrineCredentialSourceRepository
{
    /**
     * @var list<PublicKeyCredentialSource>
     */
    public array $savedViaLegacyMethod = [];

    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, PublicKeyCredentialSource::class);
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $this->savedViaLegacyMethod[] = $publicKeyCredentialSource;
    }
}
