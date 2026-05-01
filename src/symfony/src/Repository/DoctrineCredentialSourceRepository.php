<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use InvalidArgumentException;
use function sprintf;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @template T of CredentialRecord
 * @template-extends  ServiceEntityRepository<T>
 *
 * @deprecated since 5.2.0, to be removed in 6.0.0. Please create your own doctrine-based repository.
 */
class DoctrineCredentialSourceRepository extends ServiceEntityRepository implements PublicKeyCredentialSourceRepositoryInterface, CanSaveCredentialRecord, CanSaveCredentialSource
{
    /**
     * @var class-string
     */
    protected readonly string $class;

    /**
     * @param class-string<T> $class
     */
    public function __construct(ManagerRegistry $registry, string $class)
    {
        is_subclass_of(
            $class,
            CredentialRecord::class,
            true
        ) || $class === CredentialRecord::class || throw new InvalidArgumentException(
            sprintf('Invalid class. Must be an instance of "Webauthn\CredentialRecord", got "%s" instead.', $class)
        );
        $this->class = $class;
        parent::__construct($registry, $class);
    }

    public function saveCredentialRecord(CredentialRecord $credentialRecord): void
    {
        // Route PublicKeyCredentialSource through the legacy saveCredentialSource()
        // so that user subclasses overriding it (5.2.x style) keep being invoked.
        // BC promise: legacy override is honored until 6.0.
        if ($credentialRecord instanceof PublicKeyCredentialSource) {
            $this->saveCredentialSource($credentialRecord);
            return;
        }
        $this->persistCredentialRecord($credentialRecord);
    }

    /**
     * @deprecated since 5.3, use saveCredentialRecord() instead. Will be removed in 6.0.
     */
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $this->persistCredentialRecord($publicKeyCredentialSource);
    }

    /**
     * @return array<CredentialRecord>
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        /** @var array<CredentialRecord> */
        return $this->getEntityManager()
            ->createQueryBuilder()
            ->from($this->class, 'c')
            ->select('c')
            ->where('c.userHandle = :userHandle')
            ->setParameter(':userHandle', $publicKeyCredentialUserEntity->id)
            ->getQuery()
            ->execute();
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        /** @var CredentialRecord|null */
        return $this->getEntityManager()
            ->createQueryBuilder()
            ->from($this->class, 'c')
            ->select('c')
            ->where('c.publicKeyCredentialId = :publicKeyCredentialId')
            ->setParameter(':publicKeyCredentialId', base64_encode($publicKeyCredentialId))
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }

    private function persistCredentialRecord(CredentialRecord $credentialRecord): void
    {
        $this->getEntityManager()
            ->persist($credentialRecord);
        $this->getEntityManager()
            ->flush();
    }
}
