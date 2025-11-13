<?php

declare(strict_types=1);

namespace Webauthn;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\Event\AuthenticatorAttestationResponseValidationFailedEvent;
use Webauthn\Event\AuthenticatorAttestationResponseValidationSucceededEvent;
use Webauthn\Event\BackupEligibilityChangedEvent;
use Webauthn\Event\BackupStatusChangedEvent;
use Webauthn\Event\CanDispatchEvents;
use Webauthn\Event\NullEventDispatcher;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\MetadataService\CanLogData;

class AuthenticatorAttestationResponseValidator implements CanLogData, CanDispatchEvents
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

    public function setLogger(LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * @see https://www.w3.org/TR/webauthn/#registering-a-new-credential
     */
    public function check(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        string $host,
    ): PublicKeyCredentialSource {
        try {
            $this->logger->info('Checking the authenticator attestation response', [
                'authenticatorAttestationResponse' => $authenticatorAttestationResponse,
                'publicKeyCredentialCreationOptions' => $publicKeyCredentialCreationOptions,
                'host' => $host,
            ]);

            $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
                $authenticatorAttestationResponse,
                $publicKeyCredentialCreationOptions
            );

            $this->ceremonyStepManager->process(
                $publicKeyCredentialSource,
                $authenticatorAttestationResponse,
                $publicKeyCredentialCreationOptions,
                $publicKeyCredentialCreationOptions->user->id,
                $host
            );

            // Store previous backup state values to detect changes (will be null for new credentials)
            $previousBackupEligible = $publicKeyCredentialSource->backupEligible;
            $previousBackupStatus = $publicKeyCredentialSource->backupStatus;

            $publicKeyCredentialSource->counter = $authenticatorAttestationResponse->attestationObject->authData->signCount;
            $publicKeyCredentialSource->backupEligible = $authenticatorAttestationResponse->attestationObject->authData->isBackupEligible();
            $publicKeyCredentialSource->backupStatus = $authenticatorAttestationResponse->attestationObject->authData->isBackedUp();
            $publicKeyCredentialSource->uvInitialized = $authenticatorAttestationResponse->attestationObject->authData->isUserVerified();

            // Dispatch events if backup state changed
            if ($previousBackupEligible !== $publicKeyCredentialSource->backupEligible) {
                $this->eventDispatcher->dispatch(
                    new BackupEligibilityChangedEvent(
                        $publicKeyCredentialSource,
                        $previousBackupEligible,
                        $publicKeyCredentialSource->backupEligible
                    )
                );
            }
            if ($previousBackupStatus !== $publicKeyCredentialSource->backupStatus) {
                $this->eventDispatcher->dispatch(
                    new BackupStatusChangedEvent(
                        $publicKeyCredentialSource,
                        $previousBackupStatus,
                        $publicKeyCredentialSource->backupStatus
                    )
                );
            }

            $this->logger->info('The attestation is valid');
            $this->logger->debug('Public Key Credential Source', [
                'publicKeyCredentialSource' => $publicKeyCredentialSource,
            ]);
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAttestationResponseValidationSucceededEvent(
                    $authenticatorAttestationResponse,
                    $publicKeyCredentialCreationOptions,
                    $host,
                    $publicKeyCredentialSource
                )
            );
            return $publicKeyCredentialSource;
        } catch (Throwable $throwable) {
            $this->logger->error('An error occurred', [
                'exception' => $throwable,
            ]);
            $this->eventDispatcher->dispatch(
                $this->createAuthenticatorAttestationResponseValidationFailedEvent(
                    $authenticatorAttestationResponse,
                    $publicKeyCredentialCreationOptions,
                    $host,
                    $throwable
                )
            );
            throw $throwable;
        }
    }

    protected function createAuthenticatorAttestationResponseValidationSucceededEvent(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        string $host,
        PublicKeyCredentialSource $publicKeyCredentialSource
    ): AuthenticatorAttestationResponseValidationSucceededEvent {
        return new AuthenticatorAttestationResponseValidationSucceededEvent(
            $authenticatorAttestationResponse,
            $publicKeyCredentialCreationOptions,
            $host,
            $publicKeyCredentialSource
        );
    }

    protected function createAuthenticatorAttestationResponseValidationFailedEvent(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
        string $host,
        Throwable $throwable
    ): AuthenticatorAttestationResponseValidationFailedEvent {
        return new AuthenticatorAttestationResponseValidationFailedEvent(
            $authenticatorAttestationResponse,
            $publicKeyCredentialCreationOptions,
            $host,
            $throwable
        );
    }

    private function createPublicKeyCredentialSource(
        AuthenticatorAttestationResponse $authenticatorAttestationResponse,
        PublicKeyCredentialCreationOptions $publicKeyCredentialCreationOptions,
    ): PublicKeyCredentialSource {
        $attestationObject = $authenticatorAttestationResponse->attestationObject;
        $attestedCredentialData = $attestationObject->authData->attestedCredentialData;
        $attestedCredentialData !== null || throw AuthenticatorResponseVerificationException::create(
            'Not attested credential data'
        );
        $credentialId = $attestedCredentialData->credentialId;
        $credentialPublicKey = $attestedCredentialData->credentialPublicKey;
        $credentialPublicKey !== null || throw AuthenticatorResponseVerificationException::create(
            'Not credential public key available in the attested credential data'
        );
        $userHandle = $publicKeyCredentialCreationOptions->user->id;
        $transports = $authenticatorAttestationResponse->transports;

        return PublicKeyCredentialSource::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            $attestationObject->attStmt
                ->type,
            $attestationObject->attStmt
                ->trustPath,
            $attestedCredentialData->aaguid,
            $credentialPublicKey,
            $userHandle,
            $attestationObject->authData
                ->signCount,
        );
    }
}
