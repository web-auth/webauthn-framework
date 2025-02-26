<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\JsonType;
use Doctrine\DBAL\Types\Type;
use Webauthn\AttestedCredentialData;

final class AttestedCredentialDataType extends Type
{
    use SerializerTrait;

    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if (! $value instanceof AttestedCredentialData) {
            return $value;
        }

        return $this->serialize($value);
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?AttestedCredentialData
    {
        if ($value === null || $value instanceof AttestedCredentialData) {
            return $value;
        }

        return $this->deserialize($value, AttestedCredentialData::class);
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($column);
    }

    public function getName(): string
    {
        return 'attested_credential_data';
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        if (method_exists(JsonType::class, 'requiresSQLCommentHint')) {
            return (new JsonType())->requiresSQLCommentHint($platform);
        }

        return false;
    }
}
