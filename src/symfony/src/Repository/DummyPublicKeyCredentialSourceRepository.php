<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2021 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Bundle\Repository;

use LogicException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This dummy Public Key Credential Source Repository is set to allow the bundle to be installed
 * even if the real repository is not set in the configuration file.
 * This class shall be replaced in favour of your own implementation.
 */
class DummyPublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepository
{
    /**
     * @var LoggerInterface|null
     */
    private $logger;

    public function __construct(?LoggerInterface $logger = null)
    {
        $this->logger = $logger ?? new NullLogger();
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $this->logger->critical('Please change the Public Key Credential Source Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
        throw new LogicException('You are using the DummyPublicKeyCredentialSourceRepository service. Please create your own repository');
    }

    /**
     * {@inheritdoc}
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $this->logger->critical('Please change the Public Key Credential Source Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
        throw new LogicException('You are using the DummyPublicKeyCredentialSourceRepository service. Please create your own repository');
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $this->logger->critical('Please change the Public Key Credential Source Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
        throw new LogicException('You are using the DummyPublicKeyCredentialSourceRepository service. Please create your own repository');
    }
}
