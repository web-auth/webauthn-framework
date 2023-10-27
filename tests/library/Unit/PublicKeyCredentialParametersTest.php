<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\Tests\AbstractTestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class PublicKeyCredentialParametersTest extends AbstractTestCase
{
    #[Test]
    public function aPublicKeyCredentialParametersCanBeCreatedAndValueAccessed(): void
    {
        $parameters = PublicKeyCredentialParameters::create('type', 100);

        static::assertSame('type', $parameters->type);
        static::assertSame(100, $parameters->alg);
        static::assertSame('{"type":"type","alg":100}', json_encode($parameters, JSON_THROW_ON_ERROR));

        $data = $this->getSerializer()
            ->deserialize('{"type":"type","alg":100}', PublicKeyCredentialParameters::class, 'json');
        static::assertSame('type', $data->type);
        static::assertSame(100, $data->alg);
        static::assertSame('{"type":"type","alg":100}', json_encode($data, JSON_THROW_ON_ERROR));
    }
}
