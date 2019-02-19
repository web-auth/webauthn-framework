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

namespace Webauthn\Bundle\Repository;

use Assert\Assertion;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepositoryInterface;
use Doctrine\Common\Persistence\ManagerRegistry;
use Doctrine\ORM\EntityManagerInterface;
use Webauthn\AttestedCredentialData;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;

class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface, ServiceEntityRepositoryInterface
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
        Assertion::subclassOf($class, PublicKeyCredentialSource::class, \Safe\sprintf(
            'Invalid class. Must be an instance of "Webauthn\PublicKeyCredentialSource", got "%s" instead.',
            $class
        ));
        $manager = $registry->getManagerForClass($class);
        Assertion::isInstanceOf($manager, EntityManagerInterface::class, \Safe\sprintf(
            'Could not find the entity manager for class "%s". Check your Doctrine configuration to make sure it is configured to load this entity’s metadata.',
            $class
        ));

        $this->class = $class;
        $this->manager = $manager;
    }

    /**
     * @return string
     */
    protected function getClass(): string
    {
        return $this->class;
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
            ->from($this->getClass(), 'c')
            ->where('c.publicKeyCredentialId = :publicKeyCredentialId')
            ->setParameter(':publicKeyCredentialId', base64_encode($publicKeyCredentialId))
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult()
            ;
    }

    public function has(string $credentialId): bool
    {
        return null !== $this->find($credentialId);
    }

    public function get(string $credentialId): AttestedCredentialData
    {
        $credential = $this->find($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        return $credential->getAttestedCredentialData();
    }

    public function getUserHandleFor(string $credentialId): string
    {
        $credential = $this->find($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        return $credential->getUserHandle();
    }

    public function getCounterFor(string $credentialId): int
    {
        $credential = $this->find($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        return $credential->getCounter();
    }

    public function updateCounterFor(string $credentialId, int $newCounter): void
    {
        $credential = $this->find($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        $credential->setCounter($newCounter);
        $this->save($credential);
    }
}
