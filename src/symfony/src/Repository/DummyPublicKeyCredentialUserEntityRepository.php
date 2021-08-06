<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use LogicException;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * This dummy Public Key User Entity Repository is set to allow the bundle to be installed
 * even if the real repository is not set in the configuration file.
 * This class shall be replaced in favour of your own implementation.
 */
class DummyPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository
{
    public function findOneByUsername(string $username): ?PublicKeyCredentialUserEntity
    {
        throw new LogicException('Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
    }

    public function findOneByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity
    {
        throw new LogicException('Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
    }

    public function createUserEntity(string $username, string $displayName, ?string $icon): PublicKeyCredentialUserEntity
    {
        throw new LogicException('Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
    }

    public function saveUserEntity(PublicKeyCredentialUserEntity $userEntity): void
    {
        throw new LogicException('Please change the Public Key Credential User Entity Repository in the bundle configuration. See https://webauthn-doc.spomky-labs.com/the-webauthn-server/the-symfony-way#repositories-1');
    }
}
