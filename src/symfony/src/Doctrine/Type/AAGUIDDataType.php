<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use function Safe\base64_decode;

final class AAGUIDDataType extends Type
{
    /**
     * {@inheritdoc}
     */
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if (null === $value) {
            return $value;
        }

        return $value->toString();
    }

    /**
     * {@inheritdoc}
     */
    public function convertToPHPValue($value, AbstractPlatform $platform): ?UuidInterface
    {
        if (null === $value || $value instanceof UuidInterface) {
            return $value;
        }
        switch (true) {
            case 36 === mb_strlen($value, '8bit'):
                return Uuid::fromString($value);
            default: // Kept for compatibility with old format
                $decoded = base64_decode($value, true);

                return Uuid::fromBytes($decoded);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getSQLDeclaration(array $fieldDeclaration, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($fieldDeclaration);
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
