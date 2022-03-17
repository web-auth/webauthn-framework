<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Assert\Assertion;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepositoryInterface;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;

class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface, ServiceEntityRepositoryInterface
{
    private EntityManagerInterface $manager;

    private string $class;

    public function __construct(ManagerRegistry $registry, string $class)
    {
        Assertion::subclassOf($class, PublicKeyCredentialSource::class, sprintf(
            'Invalid class. Must be an instance of "Webauthn\PublicKeyCredentialSource", got "%s" instead.',
            $class
        ));
        $manager = $registry->getManagerForClass($class);
        Assertion::isInstanceOf($manager, EntityManagerInterface::class, sprintf(
            'Could not find the entity manager for class "%s". Check your Doctrine configuration to make sure it is configured to load this entity’s metadata.',
            $class
        ));

        $this->class = $class;
        $this->manager = $manager;
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource, bool $flush = true): void
    {
        $this->manager->persist($publicKeyCredentialSource);
        if ($flush) {
            $this->manager->flush();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $qb = $this->manager->createQueryBuilder();

        return $qb->select('c')
            ->from($this->getClass(), 'c')
            ->where('c.userHandle = :userHandle')
            ->setParameter(':userHandle', $publicKeyCredentialUserEntity->getId())
            ->getQuery()
            ->execute()
            ;
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $qb = $this->manager->createQueryBuilder();

        return $qb->select('c')
            ->from($this->getClass(), 'c')
            ->where('c.publicKeyCredentialId = :publicKeyCredentialId')
            ->setParameter(':publicKeyCredentialId', base64_encode($publicKeyCredentialId))
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult()
            ;
    }

    protected function getClass(): string
    {
        return $this->class;
    }

    protected function getEntityManager(): EntityManagerInterface
    {
        return $this->manager;
    }
}
