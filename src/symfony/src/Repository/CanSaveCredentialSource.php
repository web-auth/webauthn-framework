<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialSource;

/**
 * @deprecated since 5.3, use CanSaveCredentialRecord instead. Will be removed in 6.0.
 */
interface CanSaveCredentialSource
{
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void;
}
