<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Repository;

use Assert\Assertion;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepositoryInterface;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use function Safe\sprintf;
use Webauthn\PublicKeyCredentialUserEntity;

abstract class AbstractPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository, ServiceEntityRepositoryInterface
{
    /**
     * @var EntityManagerInterface
     */
    private $manager;

    /**
     * @var string
     */
    private $class;

    public function __construct(ManagerRegistry $registry, string $class)
    {
        Assertion::subclassOf($class, PublicKeyCredentialUserEntity::class, sprintf(
            'Invalid class. Must be an instance of "Webauthn\PublicKeyCredentialUserEntity", got "%s" instead.',
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

    public function findOneByUserHandle(string $id): ?PublicKeyCredentialUserEntity
    {
        $qb = $this->manager->createQueryBuilder();

        return $qb->select('u')
            ->from($this->class, 'u')
            ->where('u.id = :id')
            ->setParameter(':id', $id)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult()
            ;
    }

    public function findOneByUsername(string $name): ?PublicKeyCredentialUserEntity
    {
        $qb = $this->manager->createQueryBuilder();

        return $qb->select('u')
            ->from($this->class, 'u')
            ->where('u.name = :name')
            ->setParameter(':name', $name)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult()
            ;
    }

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void
    {
        $this->manager->persist($userEntity);
        $this->manager->flush();
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
