<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Entity;

use Assert\Assertion;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepositoryInterface;
use Doctrine\Common\Persistence\ManagerRegistry;
use Doctrine\ORM\EntityManagerInterface;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;

class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface, ServiceEntityRepositoryInterface
{
    /**
     * @var EntityManagerInterface
     */
    private $manager;

    public function __construct(ManagerRegistry $registry, string $class)
    {
        $manager = $registry->getManagerForClass($class);
        Assertion::isInstanceOf($manager, EntityManagerInterface::class, \Safe\sprintf(
            'Could not find the entity manager for class "%s". Check your Doctrine configuration to make sure it is configured to load this entity’s metadata.',
            $class
        ));

        $this->manager = $manager;
    }

    protected function getEntityManager(): EntityManagerInterface
    {
        return $this->manager;
    }

    public function save(PublicKeyCredentialSource $publicKeyCredentialSource, bool $flush = true): void
    {
        $this->manager->persist($publicKeyCredentialSource);
        if ($flush) {
            $this->manager->flush();
        }
    }

    public function find(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $qb = $this->manager->createQueryBuilder();

        return $qb->select('c')
            ->from(PublicKeyCredentialSource::class, 'c')
            ->where('c.publicKeyCredentialId = :publicKeyCredentialId')
            ->setParameter(':publicKeyCredentialId', $publicKeyCredentialId)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult()
            ;
    }
}
