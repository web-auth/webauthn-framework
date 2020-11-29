<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\Tests;

use PHPUnit\Framework\MockObject\MockObject;
use Webauthn\AttestedCredentialData;
use Webauthn\PublicKeyCredentialSource;

trait MockedPublicKeyCredentialSourceTrait
{
    protected function createPublicKeyCredentialSource(string $userHandle, int $counter, AttestedCredentialData $attestedCredentialData): MockObject
    {
        $publicKeyCredentialSource = $this->createMock(PublicKeyCredentialSource::class);
        $publicKeyCredentialSource
            ->method('getUserHandle')
            ->willReturn($userHandle)
        ;
        $publicKeyCredentialSource
            ->method('getCounter')
            ->willReturn($counter)
        ;
        $publicKeyCredentialSource
            ->method('getAttestedCredentialData')
            ->willReturn($attestedCredentialData)
        ;

        return $publicKeyCredentialSource;
    }

    abstract protected function createMock(string $originalClassName): MockObject;
}
