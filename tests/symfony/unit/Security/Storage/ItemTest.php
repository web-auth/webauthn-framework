<?php

declare(strict_types=1);

namespace Webauthn\Tests\Bundle\Unit\Security\Storage;

use PHPUnit\Framework\Attributes\DataProvider;
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

    #[Test]
    public function anItemHasNoScopeByDefault(): void
    {
        $item = Item::create($this->options(), null);

        static::assertNull($item->getScope());
    }

    #[Test]
    public function theScopeIsSetOnACopy(): void
    {
        $user = PublicKeyCredentialUserEntity::create('alice', 'user-handle', 'Alice');
        $item = Item::create($this->options(), $user, 'https://portal.example.com');

        $scopedItem = $item->withScope('controllers.request.step_up');

        static::assertNull($item->getScope());
        static::assertSame('controllers.request.step_up', $scopedItem->getScope());
        static::assertSame($item->getPublicKeyCredentialOptions(), $scopedItem->getPublicKeyCredentialOptions());
        static::assertSame($user, $scopedItem->getPublicKeyCredentialUserEntity());
        static::assertSame('https://portal.example.com', $scopedItem->getCeremonyOrigin());
    }

    #[Test]
    #[DataProvider('redemptions')]
    public function anItemIsRedeemableOnlyByTheEndpointThatIssuedIt(
        ?string $itemScope,
        ?string $endpointScope,
        bool $expected
    ): void {
        $item = Item::create($this->options(), null)->withScope($itemScope);

        static::assertSame($expected, $item->isRedeemableBy($endpointScope));
    }

    /**
     * @return iterable<string, array{?string, ?string, bool}>
     */
    public static function redemptions(): iterable
    {
        yield 'same endpoint' => ['firewall.main', 'firewall.main', true];
        yield 'another endpoint' => ['controllers.request.lax', 'firewall.main', false];
        yield 'another endpoint of the same kind' => ['controllers.request.lax', 'controllers.request.step_up', false];
        yield 'item stored without scope' => [null, 'firewall.main', true];
        yield 'endpoint without scope' => ['controllers.request.lax', null, true];
        yield 'neither has a scope' => [null, null, true];
    }

    #[Test]
    public function anItemSurvivesARoundTripThroughSerialization(): void
    {
        $item = unserialize(serialize(
            Item::create($this->options(), null, 'https://portal.example.com')->withScope('firewall.main')
        ));

        static::assertInstanceOf(Item::class, $item);
        static::assertSame('https://portal.example.com', $item->getCeremonyOrigin());
        static::assertSame('firewall.main', $item->getScope());
    }

    /**
     * Items live in the cache for the duration of a ceremony: some are still there, in their previous shape, right
     * after a deployment.
     */
    #[Test]
    public function anItemSerializedBeforeTheCeremonyOriginAndTheScopeExistedStillUnserializes(): void
    {
        $item = unserialize($this->legacyPayload());

        static::assertInstanceOf(Item::class, $item);
        static::assertNull($item->getCeremonyOrigin());
        static::assertNull($item->getScope());
        static::assertTrue($item->isRedeemableBy('firewall.main'));
        static::assertInstanceOf(PublicKeyCredentialRequestOptions::class, $item->getPublicKeyCredentialOptions());
        static::assertNull($item->getPublicKeyCredentialUserEntity());
    }

    private function options(): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create('challenge', 'example.com');
    }

    /**
     * Serialized {@see Item} as written by a bundle version that only knew the options and the user entity.
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
