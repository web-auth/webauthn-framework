<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Security\Storage;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function strlen;
use Webauthn\Bundle\Security\Storage\Item;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @internal
 */
final class ItemTest extends TestCase
{
    #[Test]
    public function theCeremonyOriginIsOptional(): void
    {
        $item = Item::create($this->options(), null);

        static::assertNull($item->getCeremonyOrigin());
    }

    #[Test]
    public function theCeremonyOriginIsCarriedAlongsideTheOptions(): void
    {
        $user = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $item = Item::create($this->options(), $user, 'https://portal.example.com');

        static::assertSame('https://portal.example.com', $item->getCeremonyOrigin());
        static::assertSame($user, $item->getPublicKeyCredentialUserEntity());
    }

    /**
     * Items live in the cache for the duration of a ceremony: some are still
     * there, in their previous shape, right after a deployment.
     */
    #[Test]
    public function anItemSerializedBeforeTheCeremonyOriginExistedStillUnserializes(): void
    {
        $item = unserialize($this->legacyPayload());

        static::assertInstanceOf(Item::class, $item);
        static::assertNull($item->getCeremonyOrigin());
        static::assertInstanceOf(PublicKeyCredentialRequestOptions::class, $item->getPublicKeyCredentialOptions());
        static::assertNull($item->getPublicKeyCredentialUserEntity());
    }

    #[Test]
    public function anItemSurvivesARoundTripThroughSerialization(): void
    {
        $item = unserialize(serialize(Item::create($this->options(), null, 'https://portal.example.com')));

        static::assertInstanceOf(Item::class, $item);
        static::assertSame('https://portal.example.com', $item->getCeremonyOrigin());
    }

    private function options(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create('challenge', 'example.com');
    }

    /**
     * Serialized {@see Item} as written by a bundle version that only knew the
     * options and the user entity.
     */
    private function legacyPayload(): string
    {
        $optionsProperty = "\0" . Item::class . "\0publicKeyCredentialOptions";
        $userEntityProperty = "\0" . Item::class . "\0publicKeyCredentialUserEntity";

        return sprintf(
            'O:%d:"%s":2:{s:%d:"%s";%ss:%d:"%s";N;}',
            strlen(Item::class),
            Item::class,
            strlen($optionsProperty),
            $optionsProperty,
            serialize($this->options()),
            strlen($userEntityProperty),
            $userEntityProperty,
        );
    }
}
