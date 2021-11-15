<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialParameters;

/**
 * @internal
 */
final class PublicKeyCredentialParametersTest extends TestCase
{
    /**
     * @test
     */
    public function anPublicKeyCredentialParametersCanBeCreatedAndValueAccessed(): void
    {
        $parameters = new PublicKeyCredentialParameters('type', 100);

        static::assertSame('type', $parameters->getType());
        static::assertSame(100, $parameters->getAlg());
        static::assertSame('{"type":"type","alg":100}', json_encode($parameters));

        $data = PublicKeyCredentialParameters::createFromString('{"type":"type","alg":100}');
        static::assertSame('type', $data->getType());
        static::assertSame(100, $data->getAlg());
        static::assertSame('{"type":"type","alg":100}', json_encode($data));
    }
}
