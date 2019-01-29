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

namespace Webauthn\Bundle\Tests\Functional;

use Webauthn\AttestedCredentialData;
use Webauthn\CredentialRepository as CredentialRepositoryInterface;

final class CredentialRepository implements CredentialRepositoryInterface
{
    /**
     * @var array
     */
    private $credentials;

    /**
     * @var array
     */
    private $counters;

    /**
     * @var array
     */
    private $userHandlers;

    public function __construct()
    {
        $this->credentials = [
            'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==' => new AttestedCredentialData(
                \Safe\base64_decode('AAAAAAAAAAAAAAAAAAAAAA==', true),
                \Safe\base64_decode('eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==', true),
                \Safe\base64_decode('pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=', true)
            ),
        ];
        $this->counters = [
            'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==' => 100,
        ];
        $this->userHandlers = [
            'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==' => 'foo',
        ];
    }

    public function has(string $credentialId): bool
    {
        return array_key_exists(base64_encode($credentialId), $this->credentials);
    }

    public function get(string $credentialId): AttestedCredentialData
    {
        if (!$this->has($credentialId)) {
            throw new \InvalidArgumentException('Not found');
        }

        return $this->credentials[base64_encode($credentialId)];
    }

    public function getUserHandleFor(string $credentialId): string
    {
        if (!$this->has($credentialId)) {
            throw new \InvalidArgumentException('Not found');
        }

        return array_key_exists(base64_encode($credentialId), $this->userHandlers) ? $this->userHandlers[base64_encode($credentialId)]: null;
    }

    public function getCounterFor(string $credentialId): int
    {
        if (!$this->has($credentialId)) {
            throw new \InvalidArgumentException('Not found');
        }

        return $this->counters[base64_encode($credentialId)];
    }

    public function updateCounterFor(string $credentialId, int $newCounter): void
    {
        if (!$this->has($credentialId)) {
            throw new \InvalidArgumentException('Not found');
        }

        $this->credentials[base64_encode($credentialId)] = $newCounter;
    }
}
