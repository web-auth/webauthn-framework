<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn;

/**
 * @deprecated Will be removed in v2.0. Please use \Webauthn\PublicKeyCredentialSourceRepository instead
 */
interface CredentialRepository
{
    public function has(string $credentialId): bool;

    public function get(string $credentialId): AttestedCredentialData;

    public function getUserHandleFor(string $credentialId): string;

    public function getCounterFor(string $credentialId): int;

    public function updateCounterFor(string $credentialId, int $newCounter): void;
}
