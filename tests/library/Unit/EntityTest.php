<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const E_USER_DEPRECATED;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\PublicKeyCredentialEntity;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class EntityTest extends AbstractTestCase
{
    #[Test]
    public function publicKeyCredentialUserEntityCanBeSerializedAndDeserialized(): void
    {
        // Given
        $user = PublicKeyCredentialUserEntity::create('name', 'id', 'display_name');

        // When
        $serialized = $this->getSerializer()
            ->serialize($user, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertSame('name', $user->name);
        static::assertSame('display_name', $user->displayName);
        static::assertSame('id', $user->id);
        static::assertSame('{"id":"aWQ","name":"name","displayName":"display_name"}', $serialized);
    }

    #[Test]
    public function publicKeyCredentialRpEntityCanBeSerializedAndDeserialized(): void
    {
        // Given
        $rp = PublicKeyCredentialRpEntity::create('', 'id');

        // When
        $serialized = $this->getSerializer()
            ->serialize($rp, 'json', [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            ]);

        // Then
        static::assertSame('', $rp->name);
        static::assertSame('id', $rp->id);
        static::assertSame('{"id":"id"}', $serialized);
    }

    #[Test]
    public function theNameOfTheAbstractEntityIsNotDeprecated(): void
    {
        // Given
        $property = new ReflectionProperty(PublicKeyCredentialEntity::class, 'name');

        // When
        $docComment = $property->getDocComment();

        // Then
        static::assertIsString($docComment);
        static::assertStringNotContainsString('@deprecated', $docComment);
    }

    #[Test]
    public function theUserEntityNameIsNotDeprecated(): void
    {
        // Given
        $property = new ReflectionProperty(PublicKeyCredentialUserEntity::class, 'name');

        // When
        $docComment = $property->getDocComment();

        // Then
        static::assertIsString($docComment);
        static::assertStringNotContainsString('@deprecated', $docComment);
    }

    #[Test]
    public function theRelyingPartyEntityNameIsDeprecated(): void
    {
        // Given
        $property = new ReflectionProperty(PublicKeyCredentialRpEntity::class, 'name');

        // When
        $docComment = $property->getDocComment();

        // Then
        static::assertSame(PublicKeyCredentialRpEntity::class, $property->getDeclaringClass()->getName());
        static::assertIsString($docComment);
        static::assertStringContainsString('@deprecated', $docComment);
        static::assertStringNotContainsString('PublicKeyCredentialUserEntity', $docComment);
    }

    #[Test]
    public function theUserEntityDoesNotTriggerAnyDeprecation(): void
    {
        // Given
        $messages = $this->collectDeprecations(
            static fn (): PublicKeyCredentialUserEntity => PublicKeyCredentialUserEntity::create(
                'name',
                'id',
                'display_name'
            )
        );

        // Then
        static::assertSame([], $messages);
    }

    #[Test]
    public function theRelyingPartyEntityWithoutNameDoesNotTriggerAnyDeprecation(): void
    {
        // Given
        $messages = $this->collectDeprecations(
            static fn (): PublicKeyCredentialRpEntity => PublicKeyCredentialRpEntity::create('', 'id')
        );

        // Then
        static::assertSame([], $messages);
    }

    #[Test]
    #[Group('legacy')]
    public function theRelyingPartyEntityWithANameTriggersASingleDeprecation(): void
    {
        // Given
        $messages = $this->collectDeprecations(
            static fn (): PublicKeyCredentialRpEntity => PublicKeyCredentialRpEntity::create('name', 'id')
        );

        // Then
        static::assertCount(1, $messages);
        static::assertStringContainsString(
            'The user agent defaults rp.name to the Relying Party ID',
            $messages[0]
        );
        static::assertStringNotContainsString('PublicKeyCredentialUserEntity', $messages[0]);
    }

    /**
     * @param callable():object $factory
     *
     * @return string[]
     */
    private function collectDeprecations(callable $factory): array
    {
        $messages = [];
        set_error_handler(static function (int $type, string $message) use (&$messages): bool {
            $messages[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $factory();
        } finally {
            restore_error_handler();
        }

        return $messages;
    }
}
