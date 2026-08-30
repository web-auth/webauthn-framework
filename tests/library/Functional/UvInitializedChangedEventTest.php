<?php

declare(strict_types=1);

namespace Webauthn\Tests\Functional;

use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Event\UvInitializedChangedEvent;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\Tests\AbstractTestCase;

/**
 * @internal
 */
final class UvInitializedChangedEventTest extends AbstractTestCase
{
    #[Test]
    public function uvInitializedChangedEventIsDispatchedWhenTransitioningFromFalseToTrue(): void
    {
        // Given
        $dispatchedEvents = [];
        $eventDispatcher = $this->createCollectingEventDispatcher($dispatchedEvents);

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('5rCH1TZzlhWn1ux5QyEFSZlmoYiKJm84FHxJZu1Zk4s=', true),
            rpId: 'webauthn.morselli.fr',
            allowCredentials: [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    base64_decode(
                        '+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==',
                        true
                    )
                ),
            ],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 60000,
        );

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                '{"id":"-uZVS9-4JgjAYI49YhdzTgHmbn638-ZNSvC0UtHkWTVS-CtTjnaSbqtzdzijByOAvEAsh-TaQJAr43FRj-dYag","type":"public-key","rawId":"+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==","response":{"authenticatorData":"ytRu25lhUyPmYiS9_oq8XVnMLSBjAp3j6bJCBIkJQ7YFAAAAlA","clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogIjVyQ0gxVFp6bGhXbjF1eDVReUVGU1psbW9ZaUtKbTg0Rkh4Slp1MVprNHMiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4ubW9yc2VsbGkuZnIiLA0KCSJ0b2tlbkJpbmRpbmciIDogDQoJew0KCQkic3RhdHVzIiA6ICJzdXBwb3J0ZWQiDQoJfQ0KfQ","signature":"MEUCIQCqFeffY4MT0dI95aS4zMiKjEb33zA/xGy3k9LTWjhgXgIgT39F2NoCc7UNLOy9N6Xf6bC4E3j056ZGGrbXcLY4F/A=","userHandle":null}}',
                PublicKeyCredential::class,
                'json'
            );

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->response);

        $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
            base64_decode(
                '+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==',
                true
            ),
            'foo',
            100,
            Uuid::fromBinary(base64_decode('+KAR84wKTRWABhcRH57cfQ==', true)),
            base64_decode(
                'pQECAyYgASFYIGCFVff/+Igs33wIEwEpwqui12XMF0tof8eDzwZNBX8eIlggcmwcE9F9W5ouuxlzKJbEJIxmUlmRHvBkyDhrqhn7Npw=',
                true
            )
        );
        $publicKeyCredentialSource->uvInitialized = false;

        $validator = $this->getAuthenticatorAssertionResponseValidator();
        $validator->setEventDispatcher($eventDispatcher);

        // When
        $validator->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );

        // Then
        $uvEvents = array_values(array_filter(
            $dispatchedEvents,
            static fn (object $event): bool => $event instanceof UvInitializedChangedEvent
        ));
        static::assertCount(1, $uvEvents, 'One UvInitializedChangedEvent should be dispatched');
        static::assertFalse($uvEvents[0]->previousValue);
        static::assertTrue($uvEvents[0]->newValue);
        static::assertSame($publicKeyCredentialSource, $uvEvents[0]->credentialRecord);
        static::assertTrue($publicKeyCredentialSource->uvInitialized);
    }

    #[Test]
    public function uvInitializedChangedEventIsNotDispatchedWhenValueStaysFalse(): void
    {
        // Given
        $dispatchedEvents = [];
        $eventDispatcher = $this->createCollectingEventDispatcher($dispatchedEvents);

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
        $publicKeyCredentialSource->uvInitialized = false;

        $validator = $this->getAuthenticatorAssertionResponseValidator();
        $validator->setEventDispatcher($eventDispatcher);

        // When
        $validator->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );

        // Then
        $uvEvents = array_filter(
            $dispatchedEvents,
            static fn (object $event): bool => $event instanceof UvInitializedChangedEvent
        );
        static::assertEmpty(
            $uvEvents,
            'No UvInitializedChangedEvent should be dispatched when the value does not change'
        );
        static::assertFalse($publicKeyCredentialSource->uvInitialized);
    }

    #[Test]
    public function uvInitializedChangedEventIsNotDispatchedWhenAlreadyTrue(): void
    {
        // Given
        $dispatchedEvents = [];
        $eventDispatcher = $this->createCollectingEventDispatcher($dispatchedEvents);

        $publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions::create(
            base64_decode('5rCH1TZzlhWn1ux5QyEFSZlmoYiKJm84FHxJZu1Zk4s=', true),
            rpId: 'webauthn.morselli.fr',
            allowCredentials: [
                PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    base64_decode(
                        '+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==',
                        true
                    )
                ),
            ],
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            timeout: 60000,
        );

        $publicKeyCredential = $this->getSerializer()
            ->deserialize(
                '{"id":"-uZVS9-4JgjAYI49YhdzTgHmbn638-ZNSvC0UtHkWTVS-CtTjnaSbqtzdzijByOAvEAsh-TaQJAr43FRj-dYag","type":"public-key","rawId":"+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==","response":{"authenticatorData":"ytRu25lhUyPmYiS9_oq8XVnMLSBjAp3j6bJCBIkJQ7YFAAAAlA","clientDataJSON":"ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogIjVyQ0gxVFp6bGhXbjF1eDVReUVGU1psbW9ZaUtKbTg0Rkh4Slp1MVprNHMiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vd2ViYXV0aG4ubW9yc2VsbGkuZnIiLA0KCSJ0b2tlbkJpbmRpbmciIDogDQoJew0KCQkic3RhdHVzIiA6ICJzdXBwb3J0ZWQiDQoJfQ0KfQ","signature":"MEUCIQCqFeffY4MT0dI95aS4zMiKjEb33zA/xGy3k9LTWjhgXgIgT39F2NoCc7UNLOy9N6Xf6bC4E3j056ZGGrbXcLY4F/A=","userHandle":null}}',
                PublicKeyCredential::class,
                'json'
            );

        static::assertInstanceOf(AuthenticatorAssertionResponse::class, $publicKeyCredential->response);

        $publicKeyCredentialSource = $this->createPublicKeyCredentialSource(
            base64_decode(
                '+uZVS9+4JgjAYI49YhdzTgHmbn638+ZNSvC0UtHkWTVS+CtTjnaSbqtzdzijByOAvEAsh+TaQJAr43FRj+dYag==',
                true
            ),
            'foo',
            100,
            Uuid::fromBinary(base64_decode('+KAR84wKTRWABhcRH57cfQ==', true)),
            base64_decode(
                'pQECAyYgASFYIGCFVff/+Igs33wIEwEpwqui12XMF0tof8eDzwZNBX8eIlggcmwcE9F9W5ouuxlzKJbEJIxmUlmRHvBkyDhrqhn7Npw=',
                true
            )
        );
        $publicKeyCredentialSource->uvInitialized = true;

        $validator = $this->getAuthenticatorAssertionResponseValidator();
        $validator->setEventDispatcher($eventDispatcher);

        // When
        $validator->check(
            $publicKeyCredentialSource,
            $publicKeyCredential->response,
            $publicKeyCredentialRequestOptions,
            'localhost',
            'foo'
        );

        // Then
        $uvEvents = array_filter(
            $dispatchedEvents,
            static fn (object $event): bool => $event instanceof UvInitializedChangedEvent
        );
        static::assertEmpty(
            $uvEvents,
            'No UvInitializedChangedEvent should be dispatched when uvInitialized is already true'
        );
        static::assertTrue($publicKeyCredentialSource->uvInitialized);
    }

    /**
     * @param list<object> $dispatchedEvents
     */
    private function createCollectingEventDispatcher(array &$dispatchedEvents): EventDispatcherInterface
    {
        return new class($dispatchedEvents) implements EventDispatcherInterface {
            /**
             * @param list<object> $events
             */
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
    }
}
