<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use JetBrains\PhpStorm\Pure;
use function Safe\json_decode;
use function Safe\json_encode;
use Webauthn\AttestedCredentialData;

final class AttestedCredentialDataType extends Type
{
    /**
     * {@inheritdoc}
     */
    public function convertToDatabaseValue($value, AbstractPlatform $platform): ?string
    {
        if (null === $value) {
            return $value;
        }

        return json_encode($value);
    }

    /**
     * {@inheritdoc}
     */
    public function convertToPHPValue($value, AbstractPlatform $platform): ?AttestedCredentialData
    {
        if (null === $value || $value instanceof AttestedCredentialData) {
            return $value;
        }
        $json = json_decode($value, true);

        return AttestedCredentialData::createFromArray($json);
    }

    /**
     * {@inheritdoc}
     */
    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getJsonTypeDeclarationSQL($column);
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public function getName(): string
    {
        return 'attested_credential_data';
    }

    /**
     * {@inheritdoc}
     */
    #[Pure]
    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }
}
