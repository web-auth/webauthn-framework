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

namespace Webauthn\ConformanceToolset\Tests\Functional;

use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\AttestedCredentialData;
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
            \Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            AttestationStatement::TYPE_NONE,
            new EmptyTrustPath(),
            \Safe\base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true),
            \Safe\base64_decode('pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=', true),
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

    /**
     * @deprecated Will be removed in v2.0. Please use the method find instead
     */
    public function has(string $credentialId): bool
    {
        return null !== $this->findOneByCredentialId($credentialId);
    }

    /**
     * @deprecated Will be removed in v2.0. Please use the method find instead
     */
    public function get(string $credentialId): AttestedCredentialData
    {
        $credential = $this->findOneByCredentialId($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        return $credential->getAttestedCredentialData();
    }

    /**
     * @deprecated Will be removed in v2.0. Please use the method find instead
     */
    public function getUserHandleFor(string $credentialId): string
    {
        $credential = $this->findOneByCredentialId($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        return $credential->getUserHandle();
    }

    /**
     * @deprecated Will be removed in v2.0. Please use the method find instead
     */
    public function getCounterFor(string $credentialId): int
    {
        $credential = $this->findOneByCredentialId($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        return $credential->getCounter();
    }

    /**
     * @deprecated Will be removed in v2.0. Please use the method save instead
     */
    public function updateCounterFor(string $credentialId, int $newCounter): void
    {
        $credential = $this->findOneByCredentialId($credentialId);
        if (null === $credential) {
            throw new \InvalidArgumentException('Invalid credential ID');
        }

        $credential->setCounter($newCounter);
        $this->saveCredentialSource($credential);
    }
}
