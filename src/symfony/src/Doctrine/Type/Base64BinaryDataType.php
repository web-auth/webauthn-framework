<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use ParagonIE\ConstantTime\Base64;
use function is_string;

final class Base64BinaryDataType extends Type
{
    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if (! is_string($value)) {
            return $value;
        }

        return Base64::encode($value);
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return $value;
        }

        return Base64::decode($value, true);
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function getName(): string
    {
        return 'base64';
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
