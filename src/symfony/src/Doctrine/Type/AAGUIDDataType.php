<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use function is_string;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;

final class AAGUIDDataType extends Type
{
    /**
     * {@inheritdoc}
     */
    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if (! $value instanceof UuidInterface) {
            return $value;
        }

        return $value->toString();
    }

    /**
     * {@inheritdoc}
     */
    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?UuidInterface
    {
        if ($value instanceof UuidInterface || ! is_string($value) || mb_strlen($value, '8bit') !== 36) {
            return $value;
        }

        return Uuid::fromString($value);
    }

    /**
     * {@inheritdoc}
     */
    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'aaguid';
    }

    /**
     * {@inheritdoc}
     */
    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
