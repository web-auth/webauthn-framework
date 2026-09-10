<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Security\Handler;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

interface FailureHandler
{
    /**
     * Three additional arguments (`?PublicKeyCredential $publicKeyCredential = null`,
     * `?PublicKeyCredentialOptions $publicKeyCredentialOptions = null` and
     * `?PublicKeyCredentialUserEntity $userEntity = null`) are passed by the bundle's
     * Assertion/Attestation response controllers when they have those values in scope
     * at the failure point (typically: deserialization succeeded but validation failed).
     *
     * They are declared as a PHPDoc-only argument list in 5.x for backwards compatibility:
     * existing implementations that have not updated their signature will silently ignore
     * the extras (PHP allows callers to pass more arguments than the implementation declares).
     * They will become real, required parameters in 6.0.
     *
     * Implementations that want to consume them should add them to their own signature now.
     */
    public function onFailure(
        Request $request,
        ?Throwable $exception = null,
        /* ?PublicKeyCredential $publicKeyCredential = null,
           ?PublicKeyCredentialOptions $publicKeyCredentialOptions = null,
           ?PublicKeyCredentialUserEntity $userEntity = null, */
    ): Response;
}
