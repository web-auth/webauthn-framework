<?php

declare(strict_types=1);

namespace Webauthn\Counter;

use Assert\Assertion;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use Webauthn\PublicKeyCredentialSource;

final class ThrowExceptionIfInvalid implements CounterChecker
{
    private LoggerInterface $logger;

    public function __construct(?LoggerInterface $logger = null)
    {
        if ($logger !== null) {
            trigger_deprecation(
                'web-auth/webauthn-symfony-bundle',
                '4.0.4',
                'Setting a logger service in the constructor is deprecated and will be removed in v5.0.0, use the method "setLogger" instead.'
            );
        }
        $this->logger = $logger ?? new NullLogger();
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function check(PublicKeyCredentialSource $publicKeyCredentialSource, int $currentCounter): void
    {
        try {
            Assertion::greaterThan($currentCounter, $publicKeyCredentialSource->getCounter(), 'Invalid counter.');
        } catch (Throwable $throwable) {
            $this->logger->error('The counter is invalid', [
                'current' => $currentCounter,
                'new' => $publicKeyCredentialSource->getCounter(),
            ]);
            throw $throwable;
        }
    }
}
