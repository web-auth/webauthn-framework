Public Key Credential Source Repository
=======================================

The credential data is managed using a repository.
The library does not provide any concrete implementation.
It is up to you to create it depending on your application constraints.

This repository must implement the interface `Webauthn\PublicKeyCredentialSourceRepository`.

For example, you might save the data in the filesystem or in a database.

# Filesystem Repository

```php
<?php
/**
 * EGroupware WebAuthn
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\WebAuthn;

use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface
{
	private $path = '/tmp/pubkey-repo.json';

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
	{
		$data = $this->read();
        if (isset($data[base64_encode($publicKeyCredentialId)]))
        {
            return PublicKeyCredentialSource::createFromArray($data[base64_encode($publicKeyCredentialId)]);
		}
		return null;
	}

    /**
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
	{
		$sources = [];
		foreach($this->read() as $data)
		{
			$source = PublicKeyCredentialSource::createFromArray($data);
			if ($source->getUserHandle() === $publicKeyCredentialUserEntity->getId())
			{
				$sources[] = $source;
			}
		}
		return $sources;
	}

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
	{
		$data = $this->read();
		$data[base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId())] = $publicKeyCredentialSource;
		$this->write($data);
	}

	private function read(): array
	{
		if (file_exists($this->path))
		{
			return json_decode(file_get_contents($this->path), true);
		}
		return [];
	}

	private function write(array $data): void
	{
		if (!file_exists($this->path))
		{
            if (!mkdir($concurrentDirectory = dirname($this->path), 0700, true) && !is_dir($concurrentDirectory)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
            }
		}
		file_put_contents($this->path, json_encode($data), LOCK_EX);
	}
}
```

# Doctrine Repository

```php
<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Repository;

use Assert\Assertion;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepositoryInterface;
use Doctrine\Common\Persistence\ManagerRegistry;
use Doctrine\ORM\EntityManagerInterface;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;

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

    protected function getClass(): string
    {
        return $this->class;
    }

    protected function getEntityManager(): EntityManagerInterface
    {
        return $this->manager;
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
}
```

*Note #1: you must add custom Doctrine types to convert plain PHP objects into your ORM. Please have a look at [this folder](https://github.com/web-auth/webauthn-framework/tree/v2.0/src/symfony/src/Doctrine/Type)*.
*Note #2: if you use Symfony, this repository already exists and custom doctrine types are automatically registered.
