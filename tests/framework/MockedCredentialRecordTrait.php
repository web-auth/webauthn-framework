<?php

declare(strict_types=1);

namespace Webauthn\Tests;

use Symfony\Component\Uid\AbstractUid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TrustPath\TrustPath;

trait MockedCredentialRecordTrait
{
    protected function createCredentialRecord(
        string $id,
        string $userHandle,
        int $counter,
        AbstractUid $aaguid,
        $publicKey,
        array $transport = [],
        string $attestationType = 'none',
        ?TrustPath $trustPath = null
    ): CredentialRecord {
        return CredentialRecord::create(
            $id,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transport,
            $attestationType,
            $trustPath ?? EmptyTrustPath::create(),
            $aaguid,
            $publicKey,
            $userHandle,
            $counter
        );
    }
}
