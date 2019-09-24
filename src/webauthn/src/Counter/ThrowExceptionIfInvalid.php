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

namespace Webauthn\Counter;

use Assert\Assertion;
use Webauthn\PublicKeyCredentialSource;

final class ThrowExceptionIfInvalid implements CounterChecker
{
    public function check(PublicKeyCredentialSource $publicKeyCredentialSource, int $currentCounter): void
    {
        Assertion::greaterThan($currentCounter, $publicKeyCredentialSource->getCounter(), 'Invalid counter.');
    }
}
