Webauthn Symfony Bundle
=======================

# Installation

Install the bundle with Composer: `web-authn/webauthn-symfony-bundle`

If you are using Symfony Flex then the bundle will automatically be installed.
Otherwise you need to add it in your `AppKernel.php` file:

```php
<?php
// app/AppKernel.php

public function registerBundles()
{
    $bundles = [
        // ...
        new Webauthn\Bundle\WebauthnBundle(),
    ];
}
```

# Create Classes

This bundle needs classes and sevices to work:

* The credential object: it represents a credential from a security device,
* The credential repository: it will manage all credentials,
* The token binding handler: security feature from the [RFC8471](https://tools.ietf.org/html/rfc8471).

## Credential

A credential corresponds to the attested data received from a device and the current counter.
Hereafter an example using Doctrine ORM. This entity can be enhanced and may also have a `name` or `description` to ease the management of this credential by the user or the administrator of your application.

Please note that:

* The class `Webauthn\AttestedCredentialData` has a Doctrine Type `attested_credential_data` and can easily be stored/retreived from your database.
* No relationship between the credential and your user is present in this example. You may need to add such information (`OneToMany`/`ManyToOne` relationship).

```php
<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Webauthn\AttestedCredentialData;

/**
 * @ORM\Entity(repositoryClass="App\Entity\CredentialRepository")
 * @ORM\Table(name="credentials",indexes={@Index(name="search_idx", columns={"credential_id"})})
 */
class Credential
{
    /**
     * @var string
     *
     * @ORM\Id
     * @ORM\Column(type="string", length=255)
     */
    private $id;

    /**
     * @var string
     *
     * @ORM\Column(type="blob", length=255)
     */
    private $credential_id;

    /**
     * @var AttestedCredentialData
     *
     * @ORM\Column(type="attested_credential_data")
     */
    private $attested_credential_data;

    /**
     * @var int
     *
     * @ORM\Column(type="integer")
     */
    private $counter;

    public function __construct(string uid, AttestedCredentialData $attested_credential_data, int $counter)
    {
        $this->id = $id;
        $this->credential_id = $attested_credential_data->getCredentialId();
        $this->attested_credential_data = $attested_credential_data;
        $this->counter = $counter;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getAttestedCredentialData(): AttestedCredentialData
    {
        return $this->attested_credential_data;
    }

    public function getCounter(): int
    {
        return $this->counter;
    }

    public function setCounter(int $counter): void
    {
        $this->counter = $counter;
    }
}
```

## Credential Repository

The credential repository must implement `Webauthn\CredentialRepository`.
In this following example, we will use Doctrine and retreive/save Credential objects defined earlier.

Feel free to add methods e.g. to get credentials associated to a user.

```php
<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepositoryInterface;
use Doctrine\Common\Persistence\ManagerRegistry;
use Doctrine\ORM\EntityManagerInterface;
use LogicException;
use Webauthn\AttestedCredentialData;
use Webauthn\CredentialRepository as CredentialRepositoryInterface;

final class CredentialRepository implements CredentialRepositoryInterface, ServiceEntityRepositoryInterface
{
    /**
     * @var EntityManagerInterface
     */
    private $manager;

    public function __construct(ManagerRegistry $registry)
    {
        $manager = $registry->getManagerForClass(Credential::class);

        if (null === $manager) {
            throw new LogicException(sprintf(
                'Could not find the entity manager for class "%s". Check your Doctrine configuration to make sure it is configured to load this entity’s metadata.',
                Credential::class
            ));
        }

        $this->manager = $manager;
    }

    // MANDATORY: this function saves a Credential object in the database
    public function save(Credential $credential): void
    {
        $this->manager->persist($credential);
        $this->manager->flush();
    }

    // MANDATORY: this function check if the credential ID is managed
    public function has(string $credentialId): bool
    {
        return null !== $this->find($credentialId);
    }

    // MANDATORY: this function retreive the Credential object based on the credential ID
    public function get(string $credentialId): AttestedCredentialData
    {
        $credential = $this->find($credentialId);
        if (!$credential instanceof Credential) {
            throw new \InvalidArgumentException('Not found');
        }

        return $credential->getAttestedCredentialData();
    }

    // This function prepare and execute a query to find a credential 
    public function find(string $credentialId): ?Credential
    {
        $qb = $this->manager->createQueryBuilder();

        return $qb->select('c')
            ->from(Credential::class, 'c')
            ->where('c.credential_id = :credential_id')
            ->setParameter(':credential_id', $credentialId)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult()
        ;
    }

    // MANDATORY: this function retreive the current counter for the given credential ID
    public function getCounterFor(string $credentialId): int
    {
        $credential = $this->find($credentialId);
        if (!$credential instanceof Credential) {
            throw new \InvalidArgumentException('Not found');
        }

        return $credential->getCounter();
    }

    // MANDATORY: this function update the current counter for the given credential ID
    public function updateCounterFor(string $credentialId, int $newCounter): void
    {
        $credential = $this->find($credentialId);
        if (!$credential instanceof Credential) {
            throw new \InvalidArgumentException('Not found');
        }

        $credential->setCounter($newCounter);
        $this->manager->persist($credential);
        $this->manager->flush();
    }
}
```

## Token Binding Handler

The [RFC8471](https://tools.ietf.org/html/rfc8471) adds a security feature to bind the response from a security device with the current TLS session. With this feature, it is more complicated for an attacker to perform replay attacks.

As this feature is not fully supported by browsers and servers and implementations are very rare, a Token Binding Handler is present in the library and this bundle.
At the moment this feature is not supported by the library, but using this handler, you can decide the strategy to adopt if token binding is present in the security device responses.

Available handlers (Symfony services):

* Ignore: use `Webauthn\TokenBinding\IgnoreTokenBindingHandler` to ignore the Token Binding
* Error (default): use `Webauthn\TokenBinding\TokenBindingNotSupportedHandler` and throw an exception

See also [#2](https://github.com/web-auth/webauthn-framework/issues/2) for more information.

# Configure the Bundle

In your application configuration, you have to add a `webauthn` section:

```yaml
#...
webauthn:
    credential_repository: 'App\Entity\CredentialRepository'
    token_binding_support_handler: 'Webauthn\TokenBinding\IgnoreTokenBindingHandler' # Default is 'Webauthn\TokenBinding\TokenBindingNotSupportedHandler'
```

# Usage

[TO BE CONTINUED]
