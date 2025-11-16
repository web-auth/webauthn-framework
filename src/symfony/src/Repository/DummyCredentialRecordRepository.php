<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use LogicException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Webauthn\CredentialRecord;
use Webauthn\MetadataService\CanLogData;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This dummy Credential Record Repository is set to allow the bundle to be installed even if the real
 * repository is not set in the configuration file. This class shall be replaced in favour of your own implementation.
 */
class DummyCredentialRecordRepository implements CredentialRecordRepositoryInterface, CanLogData
{
    public function __construct(
        private LoggerInterface $logger = new NullLogger()
    ) {
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $this->throwException();
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        $this->throwException();
    }

    private function throwException(): never
    {
        $this->logger->critical(
            'Please change the Credential Record Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1'
        );
        throw new LogicException(
            'You are using the DummyCredentialRecordRepository service. Please create your own repository'
        );
    }
}
