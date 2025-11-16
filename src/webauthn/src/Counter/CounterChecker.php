<?php

declare(strict_types=1);

namespace Webauthn\Counter;

use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialSource;

interface CounterChecker
{
    public function check(CredentialRecord|PublicKeyCredentialSource $credentialRecord, int $currentCounter): void;
}
