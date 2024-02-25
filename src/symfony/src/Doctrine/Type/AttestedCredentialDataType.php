<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Webauthn\AttestedCredentialData;
use function is_array;
use function is_string;
use const JSON_THROW_ON_ERROR;

final class AttestedCredentialDataType extends Type
{
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return $value;
        }
        if (is_string($value)) {
            return $value;
        }
        if ($value instanceof AttestedCredentialData) {
            return json_encode($value, JSON_THROW_ON_ERROR);
        }

        return null;
    }

    public function convertToPHPValue($value, AbstractPlatform $platform): ?AttestedCredentialData
    {
        if ($value === null || $value instanceof AttestedCredentialData) {
            return $value;
        }
        if (is_string($value)) {
            $json = json_decode($value, true, 512, JSON_THROW_ON_ERROR);
            if (is_array($json)) {
                return AttestedCredentialData::createFromArray($json);
            }
        }

        return null;
    }

    public function getSQLDeclaration(array $fieldDeclaration, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($fieldDeclaration);
    }

    public function getName(): string
    {
        return 'attested_credential_data';
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
