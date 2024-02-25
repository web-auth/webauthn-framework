<?php

declare(strict_types=1);

namespace Webauthn;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\Event\AuthenticatorAssertionResponseValidationFailedEvent;
use Webauthn\Event\AuthenticatorAssertionResponseValidationSucceededEvent;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CanLogData;
use Webauthn\MetadataService\Event\CanDispatchEvents;
use Webauthn\MetadataService\Event\NullEventDispatcher;

class AuthenticatorAssertionResponseValidator implements CanLogData, CanDispatchEvents
{
    private LoggerInterface $logger;

    private EventDispatcherInterface $eventDispatcher;

    public function __construct(
        private readonly CeremonyStepManager $ceremonyStepManager
    ) {
        $this->eventDispatcher = new NullEventDispatcher();
        $this->logger = new NullLogger();
    }

    public static function create(CeremonyStepManager $ceremonyStepManager): self
    {
        return new self($ceremonyStepManager);
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#verifying-assertion
     */
    public function check(
        PublicKeyCredentialSource $publicKeyCredentialSource,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        string $host,
        ?string $userHandle,
    ): PublicKeyCredentialSource {
        try {
            $this->logger->info('Checking the authenticator assertion response', [
                'publicKeyCredentialSource' => $publicKeyCredentialSource,
                'authenticatorAssertionResponse' => $authenticatorAssertionResponse,
                'publicKeyCredentialRequestOptions' => $publicKeyCredentialRequestOptions,
                'host' => $host,
                'userHandle' => $userHandle,
            ]);

            $this->ceremonyStepManager->process(
                $publicKeyCredentialSource,
                $authenticatorAssertionResponse,
                $publicKeyCredentialRequestOptions,
                $userHandle,
                $host
            );

            $publicKeyCredentialSource->counter = $authenticatorAssertionResponse->authenticatorData->signCount; //26.1.
            $publicKeyCredentialSource->backupEligible = $authenticatorAssertionResponse->authenticatorData->isBackupEligible(); //26.2.
            $publicKeyCredentialSource->backupStatus = $authenticatorAssertionResponse->authenticatorData->isBackedUp(); //26.2.
            if ($publicKeyCredentialSource->uvInitialized === false) {
                $publicKeyCredentialSource->uvInitialized = $authenticatorAssertionResponse->authenticatorData->isUserVerified(); //26.3.
            }
            /*
             * 26.3.
             * OPTIONALLY, if response.attestationObject is present, update credentialRecord.attestationObject to the value of response.attestationObject and update credentialRecord.attestationClientDataJSON to the value of response.clientDataJSON.
             */

            //All good. We can continue.
            $this->logger->info('The assertion is valid');
            $this->logger->debug('Public Key Credential Source', [
                'publicKeyCredentialSource' => $publicKeyCredentialSource,
            ]);
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAssertionResponseValidationSucceededEvent(
                    $authenticatorAssertionResponse,
                    $publicKeyCredentialRequestOptions,
                    $host,
                    $userHandle,
                    $publicKeyCredentialSource
                )
            );
            // 27.
            return $publicKeyCredentialSource;
        } catch (AuthenticatorResponseVerificationException $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAssertionResponseValidationFailedEvent(
                    $publicKeyCredentialSource,
                    $authenticatorAssertionResponse,
                    $publicKeyCredentialRequestOptions,
                    $host,
                    $userHandle,
                    $throwable
                )
            );
            throw $throwable;
        }
    }

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    protected function createAuthenticatorAssertionResponseValidationSucceededEvent(
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        string $host,
        ?string $userHandle,
        PublicKeyCredentialSource $publicKeyCredentialSource
    ): AuthenticatorAssertionResponseValidationSucceededEvent {
        return new AuthenticatorAssertionResponseValidationSucceededEvent(
            $authenticatorAssertionResponse,
            $publicKeyCredentialRequestOptions,
            $host,
            $userHandle,
            $publicKeyCredentialSource
        );
    }

    protected function createAuthenticatorAssertionResponseValidationFailedEvent(
        PublicKeyCredentialSource $publicKeyCredentialSource,
        AuthenticatorAssertionResponse $authenticatorAssertionResponse,
        PublicKeyCredentialRequestOptions $publicKeyCredentialRequestOptions,
        string $host,
        ?string $userHandle,
        Throwable $throwable
    ): AuthenticatorAssertionResponseValidationFailedEvent {
        return new AuthenticatorAssertionResponseValidationFailedEvent(
            $publicKeyCredentialSource,
            $authenticatorAssertionResponse,
            $publicKeyCredentialRequestOptions,
            $host,
            $userHandle,
            $throwable
        );
    }
}
