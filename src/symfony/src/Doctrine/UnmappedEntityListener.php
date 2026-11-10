<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Doctrine;

use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use function is_subclass_of;
use LogicException;
use function sprintf;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialEntity;

/**
 * Refuses the entities that still expect the Doctrine mapping removed in 6.0.0.
 *
 * Up to 5.4, an entity extending `Webauthn\CredentialRecord` or `Webauthn\PublicKeyCredentialEntity` got its columns
 * from the mapping provided by the bundle. Without it, Doctrine only knows the properties declared by the entity
 * itself, and a schema update would drop the columns holding the credential records. Such an entity is refused when
 * its metadata is loaded, before any schema or query uses it.
 *
 * An entity mapping the inherited properties itself, for instance through an XML mapping of the parent class, is
 * accepted: the property identifying the records of each class is enough to tell it apart.
 *
 * @see https://github.com/web-auth/webauthn-framework/issues/1007
 * @internal
 */
final class UnmappedEntityListener
{
    private const IDENTIFYING_PROPERTIES = [
        CredentialRecord::class => 'publicKeyCredentialId',
        PublicKeyCredentialEntity::class => 'name',
    ];

    public function loadClassMetadata(LoadClassMetadataEventArgs $event): void
    {
        $metadata = $event->getClassMetadata();
        if ($metadata->isMappedSuperclass) {
            return;
        }
        $className = $metadata->getName();
        foreach (self::IDENTIFYING_PROPERTIES as $parentClass => $property) {
            if (! is_subclass_of($className, $parentClass) || $metadata->hasField($property)) {
                continue;
            }
            throw new LogicException(sprintf(
                'The entity "%s" extends "%s" without mapping its properties. The bundle no longer provides this mapping since 6.0.0: map an entity of your application and convert it from and to "%s" in your repository instead.',
                $className,
                $parentClass,
                $parentClass
            ));
        }
    }
}
