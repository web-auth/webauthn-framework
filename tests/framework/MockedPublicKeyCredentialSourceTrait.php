<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use Ramsey\Uuid\UuidInterface;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TrustPath\TrustPath;

trait MockedPublicKeyCredentialSourceTrait
{
    protected function createPublicKeyCredentialSource(
        string $id,
        string $userHandle,
        int $counter,
        UuidInterface $aaguid,
        $publicKey,
        array $transport = [],
        string $attestationType = 'none',
        ?TrustPath $trustPath = null
    ): PublicKeyCredentialSource {
        return new PublicKeyCredentialSource(
            $id,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transport,
            $attestationType,
            $trustPath ?? new EmptyTrustPath(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter
        );
    }
}
