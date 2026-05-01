<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\CredentialRecord;

/**
 * Interface for repositories that can save credential records.
 */
interface CanSaveCredentialRecord
{
    public function saveCredentialRecord(CredentialRecord $credentialRecord): void;
}
