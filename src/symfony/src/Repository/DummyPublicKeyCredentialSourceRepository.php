<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use LogicException;
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
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        throw new LogicException('Please change the Public Key Credential Source Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        throw new LogicException('Please change the Public Key Credential Source Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
    }

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        throw new LogicException('Please change the Public Key Credential Source Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
    }
}
