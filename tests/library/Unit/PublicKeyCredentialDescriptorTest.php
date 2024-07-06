<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class PublicKeyCredentialDescriptorTest extends AbstractTestCase
{
    #[Test]
    public function anPublicKeyCredentialDescriptorCanBeCreatedAndValueAccessed(): void
    {
        $descriptor = PublicKeyCredentialDescriptor::create('type', 'id', ['transport']);

        static::assertSame('type', $descriptor->type);
        static::assertSame('id', $descriptor->id);
        static::assertSame(['transport'], $descriptor->transports);
        static::assertSame(
            '{"type":"type","id":"aWQ","transports":["transport"]}',
            $this->getSerializer()
                ->serialize($descriptor, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ])
        );
    }
}
