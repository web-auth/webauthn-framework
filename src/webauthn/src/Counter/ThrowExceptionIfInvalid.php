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

namespace Webauthn\Counter;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Webauthn\Exception\InvalidCounterException;
use Webauthn\PublicKeyCredentialSource;

final class ThrowExceptionIfInvalid implements CounterChecker
{
    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(?LoggerInterface $logger = null)
    {
        $this->logger = $logger ?? new NullLogger();
    }

    public function check(PublicKeyCredentialSource $publicKeyCredentialSource, int $responseCounter): void
    {
        if ($responseCounter > $publicKeyCredentialSource->getCounter()) {
            return;
        }

        $this->logger->error('The counter is invalid', [
            'current' => $responseCounter,
            'new' => $publicKeyCredentialSource->getCounter(),
        ]);
        throw new InvalidCounterException($responseCounter, $publicKeyCredentialSource->getCounter(), 'The counter is invalid');
    }
}
