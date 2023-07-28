<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialDescriptor;

/**
 * @internal
 */
final class PublicKeyCredentialDescriptorTest extends TestCase
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
            json_encode($descriptor, JSON_THROW_ON_ERROR)
        );
    }
}
