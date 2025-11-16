<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialSource;

/**
 * Interface for repositories that can save credential records.
 */
interface CanSaveCredentialRecord
{
    public function saveCredentialSource(CredentialRecord|PublicKeyCredentialSource $credentialRecord): void;
}
