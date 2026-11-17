<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine;

use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use function is_subclass_of;
use function trigger_deprecation;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Reports the entities relying on the Doctrine mapping provided by the bundle.
 *
 * The bundle maps `Webauthn\CredentialRecord`, `Webauthn\PublicKeyCredentialUserEntity` and
 * `Webauthn\PublicKeyCredentialEntity` as mapped superclasses. An entity extending one of them gets its columns from
 * that mapping, which is deprecated together with `DoctrineCredentialSourceRepository`. An entity of the application
 * that does not extend these classes is not concerned, even though the mapping is still registered: a mapped
 * superclass nobody extends creates no table.
 *
 * The mapped superclasses are listed from the most specific one, so that the message names the class the entity
 * actually extends.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1007
 * @internal
 */
final class DeprecatedMappingListener
{
    private const MAPPED_SUPERCLASSES = [
        CredentialRecord::class,
        PublicKeyCredentialUserEntity::class,
        PublicKeyCredentialEntity::class,
    ];

    public function loadClassMetadata(LoadClassMetadataEventArgs $event): void
    {
        $metadata = $event->getClassMetadata();
        if ($metadata->isMappedSuperclass) {
            return;
        }
        $className = $metadata->getName();
        foreach (self::MAPPED_SUPERCLASSES as $mappedSuperclass) {
            if (! is_subclass_of($className, $mappedSuperclass)) {
                continue;
            }
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '5.4.0',
                'The entity "%s" extends "%s" and relies on the Doctrine mapping provided by the bundle. This mapping is deprecated and will be removed in 6.0.0. Map an entity of your application and convert it from and to "%s" in your repository instead.',
                $className,
                $mappedSuperclass,
                $mappedSuperclass
            );

            return;
        }
    }
}
