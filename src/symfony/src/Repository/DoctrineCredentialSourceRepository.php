<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use InvalidArgumentException;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use function sprintf;

/**
 * @template T of PublicKeyCredentialSource
 * @template-extends  ServiceEntityRepository<T>
 */
class DoctrineCredentialSourceRepository extends ServiceEntityRepository implements PublicKeyCredentialSourceRepositoryInterface, CanSaveCredentialSource
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
        is_subclass_of($class, PublicKeyCredentialSource::class) || throw new InvalidArgumentException(sprintf(
            'Invalid class. Must be an instance of "Webauthn\PublicKeyCredentialSource", got "%s" instead.',
            $class
        ));
        $this->class = $class;
        parent::__construct($registry, $class);
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $this->getEntityManager()
            ->persist($publicKeyCredentialSource);
        $this->getEntityManager()
            ->flush();
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return $this->getEntityManager()
            ->createQueryBuilder()
            ->from($this->class, 'c')
            ->select('c')
            ->where('c.userHandle = :userHandle')
            ->setParameter(':userHandle', $publicKeyCredentialUserEntity->id)
            ->getQuery()
            ->execute();
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
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

    /**
     * @deprecated since 4.7.2 and will be removed in 5.0.0. Please use the property instead.
     */
    protected function getClass(): string
    {
        return $this->class;
    }
}
