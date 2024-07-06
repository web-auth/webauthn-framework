<?php

declare(strict_types=1);

namespace Webauthn\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\Tests\AbstractTestCase;

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
        static::assertSame('{"type":"type","alg":100}', $this->getSerializer()->serialize($parameters, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));

        $data = $this->getSerializer()
            ->deserialize('{"type":"type","alg":100}', PublicKeyCredentialParameters::class, 'json');
        static::assertSame('type', $data->type);
        static::assertSame(100, $data->alg);
        static::assertSame('{"type":"type","alg":100}', $this->getSerializer()->serialize($data, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
        ]));
    }
}
