<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Event\BackupEligibilityChangedEvent;
use Webauthn\Event\BackupStatusChangedEvent;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class BackupStateEventsTest extends AbstractTestCase
{
    #[Test]
    public function backupStateEventsAreDispatchedWhenChanged(): void
    {
        $dispatchedEvents = [];
        $eventDispatcher = new class($dispatchedEvents) implements EventDispatcherInterface {
            public function __construct(
                private array &$events
            ) {
            }

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true),
            rpId: 'localhost',
            allowCredentials: [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64UrlSafe::decode(
                        'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                        true
                    )
                ),
            ],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 60000,
        );

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}',
                PublicKeyCredential::class,
                'json'
            );

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->response);

        // Create a credential source with initial backup state values
        $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            'foo',
            100,
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            base64_decode(
                'pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=',
                true
            )
        );

        // Set initial backup state values different from what's in the authenticatorData
        // The authenticatorData has BE=false and BS=false, so we set them to true to trigger a change
        $publicKeyCredentialSource->backupEligible = true;
        $publicKeyCredentialSource->backupStatus = true;

        $validator = $this->getAuthenticatorAssertionResponseValidator();
        $validator->setEventDispatcher($eventDispatcher);

        $validator->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );

        // Filter to only backup state events
        $backupEvents = array_filter(
            $dispatchedEvents,
            fn ($event) => $event instanceof BackupEligibilityChangedEvent || $event instanceof BackupStatusChangedEvent
        );

        // Verify that events were dispatched
        static::assertNotEmpty($backupEvents, 'Backup state change events should have been dispatched');

        $backupEligibilityEvents = array_values(array_filter(
            $backupEvents,
            fn ($event) => $event instanceof BackupEligibilityChangedEvent
        ));
        $backupStatusEvents = array_values(array_filter(
            $backupEvents,
            fn ($event) => $event instanceof BackupStatusChangedEvent
        ));

        // Verify BackupEligibilityChangedEvent
        static::assertCount(1, $backupEligibilityEvents, 'One BackupEligibilityChangedEvent should be dispatched');
        $eligibilityEvent = $backupEligibilityEvents[0];
        static::assertTrue($eligibilityEvent->previousValue);
        static::assertFalse($eligibilityEvent->newValue);
        static::assertSame($publicKeyCredentialSource, $eligibilityEvent->publicKeyCredentialSource);

        // Verify BackupStatusChangedEvent
        static::assertCount(1, $backupStatusEvents, 'One BackupStatusChangedEvent should be dispatched');
        $statusEvent = $backupStatusEvents[0];
        static::assertTrue($statusEvent->previousValue);
        static::assertFalse($statusEvent->newValue);
        static::assertSame($publicKeyCredentialSource, $statusEvent->publicKeyCredentialSource);
    }

    #[Test]
    public function backupStateEventsAreNotDispatchedWhenUnchanged(): void
    {
        $dispatchedEvents = [];
        $eventDispatcher = new class($dispatchedEvents) implements EventDispatcherInterface {
            public function __construct(
                private array &$events
            ) {
            }

            public function dispatch(object $event): object
            {
                $this->events[] = $event;
                return $event;
            }
        };

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('G0JbLLndef3a0Iy3S2sSQA8uO4SO/ze6FZMAuPI6+xI=', true),
            rpId: 'localhost',
            allowCredentials: [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    Base64UrlSafe::decode(
                        'eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w',
                        true
                    )
                ),
            ],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 60000,
        );

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                '{"id":"eHouz_Zi7-BmByHjJ_tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp_B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB-w","type":"public-key","rawId":"eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==","response":{"authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAew","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJHMEpiTExuZGVmM2EwSXkzUzJzU1FBOHVPNFNPX3plNkZaTUF1UEk2LXhJIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","signature":"MEUCIEY/vcNkbo/LdMTfLa24ZYLlMMVMRd8zXguHBvqud9AJAiEAwCwpZpvcMaqCrwv85w/8RGiZzE+gOM61ffxmgEDeyhM=","userHandle":null}}',
                PublicKeyCredential::class,
                'json'
            );

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->response);

        // Create a credential source with backup state values that match what's in the authenticatorData
        $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
            base64_decode(
                'eHouz/Zi7+BmByHjJ/tx9h4a1WZsK4IzUmgGjkhyOodPGAyUqUp/B9yUkflXY3yHWsNtsrgCXQ3HjAIFUeZB+w==',
                true
            ),
            'foo',
            100,
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            base64_decode(
                'pQECAyYgASFYIJV56vRrFusoDf9hm3iDmllcxxXzzKyO9WruKw4kWx7zIlgg/nq63l8IMJcIdKDJcXRh9hoz0L+nVwP1Oxil3/oNQYs=',
                true
            )
        );

        // Set backup state values to match what's in the authenticatorData (BE=false, BS=false)
        $publicKeyCredentialSource->backupEligible = false;
        $publicKeyCredentialSource->backupStatus = false;

        $validator = $this->getAuthenticatorAssertionResponseValidator();
        $validator->setEventDispatcher($eventDispatcher);

        $validator->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );

        // Filter to only backup state events
        $backupEvents = array_filter(
            $dispatchedEvents,
            fn ($event) => $event instanceof BackupEligibilityChangedEvent || $event instanceof BackupStatusChangedEvent
        );

        // Verify that no backup state events were dispatched since values didn't change
        static::assertEmpty(
            $backupEvents,
            'No backup state change events should be dispatched when values are unchanged'
        );
    }
}
