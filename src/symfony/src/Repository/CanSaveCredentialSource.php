<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Repository;

use Webauthn\PublicKeyCredentialSource;

interface CanSaveCredentialSource
{
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void;
}
