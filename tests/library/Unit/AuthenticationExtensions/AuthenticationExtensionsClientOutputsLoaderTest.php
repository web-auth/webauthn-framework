<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit\AuthenticationExtensions;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\OtherObject\TrueObject;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputs;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientOutputsLoader;
use Webauthn\Exception\AuthenticationExtensionException;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class AuthenticationExtensionsClientOutputsLoaderTest extends AbstractTestCase
{
    #[Test]
    public function theExtensionsCanBeLoaded(): void
    {
        $cbor = new MapObject([new MapItem(new ByteStringObject('loc'), new TrueObject())]);

        $extensions = AuthenticationExtensionsClientOutputsLoader::load($cbor);

        static::assertInstanceOf(AuthenticationExtensionsClientOutputs::class, $extensions);
        static::assertCount(1, $extensions);
        static::assertSame('{"loc":true}', $this->getSerializer()->serialize($extensions, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
    }

    #[Test]
    public function theCBORObjectIsInvalid(): void
    {
        $this->expectException(AuthenticationExtensionException::class);
        $this->expectExceptionMessage('Invalid extension object');
        $cbor = new ByteStringObject('loc');

        AuthenticationExtensionsClientOutputsLoader::load($cbor);
    }
}
