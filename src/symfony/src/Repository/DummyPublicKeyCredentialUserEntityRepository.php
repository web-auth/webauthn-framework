<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use LogicException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This dummy Public Key User Entity Repository is set to allow the bundle to be installed even if the real repository
 * is not set in the configuration file. This class shall be replaced in favour of your own implementation.
 */
class DummyPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository
{
    private LoggerInterface $logger;

    public function __construct(?LoggerInterface $logger = null)
    {
        $this->logger = $logger ?? new NullLogger();
    }

    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
    {
        $this->logger->critical(
            'Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1'
        );
        throw new LogicException(
            'You are using the DummyPublicKeyCredentialUserEntityRepository service. Please create your own repository'
        );
    }

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
    {
        $this->logger->critical(
            'Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1'
        );
        throw new LogicException(
            'You are using the DummyPublicKeyCredentialUserEntityRepository service. Please create your own repository'
        );
    }

    public function createUserEntity(
        string $username,
        string $displayName,
        ?string $icon
    ): PublicKeyCredentialUserEntity {
        $this->logger->critical(
            'Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1'
        );
        throw new LogicException(
            'You are using the DummyPublicKeyCredentialUserEntityRepository service. Please create your own repository'
        );
    }

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void
    {
        $this->logger->critical(
            'Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1'
        );
        throw new LogicException(
            'You are using the DummyPublicKeyCredentialUserEntityRepository service. Please create your own repository'
        );
    }
}
