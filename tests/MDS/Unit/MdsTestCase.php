<?php

declare(strict_types=1);

namespace Webauthn\Tests\MetadataService\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\MetadataService\Denormalizer\MetadataStatementSerializerFactory;

/**
 * @internal
 */
abstract class MdsTestCase extends TestCase
{
    protected function getSerializer(): SerializerInterface
    {
        return MetadataStatementSerializerFactory::create();
    }
}
