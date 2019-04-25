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

namespace Webauthn\Bundle\Tests\Functional;

use function Safe\base64_decode;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository as PublicKeyCredentialSourceRepositoryInterface;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

final class PublicKeyCredentialSourceRepository implements PublicKeyCredentialSourceRepositoryInterface
{
    /**
     * @var PublicKeyCredentialSource[]
     */
    private $credentials;

    public function __construct()
    {
        $pkcs1 = new PublicKeyCredentialSource(
            base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            new EmptyTrustPath(),
            base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true),
            base64_decode('pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=', true),
            'foo',
            100
        );
        $this->saveCredentialSource($pkcs1);
    }

    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return 'foo' === $publicKeyCredentialUserEntity->getId() ? $this->credentials : [];
    }

    public function findOneByCredentialId(string $credentialId): ?PublicKeyCredentialSource
    {
        if (!\array_key_exists(base64_encode($credentialId), $this->credentials)) {
            return null;
        }

        return $this->credentials[base64_encode($credentialId)];
    }

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $this->credentials[base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId())] = $publicKeyCredentialSource;
    }
}
