<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use function assert;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\JsonType;
use function is_string;
use Webauthn\AttestedCredentialData;

final class AttestedCredentialDataType extends JsonType
{
    use SerializerTrait;

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if (! $value instanceof AttestedCredentialData) {
            assert($value === null || is_string($value));
            return $value;
        }

        return $this->serialize($value);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?AttestedCredentialData
    {
        if ($value === null || $value instanceof AttestedCredentialData) {
            return $value;
        }

        /** @var string $value */
        return $this->deserialize($value, AttestedCredentialData::class);
    }

    public function getName(): string
    {
        return 'attested_credential_data';
    }
}
