<?php

declare(strict_types=1);

namespace Webauthn\Bundle\Service;

use InvalidArgumentException;
use function sprintf;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;
use Webauthn\Signal\AllAcceptedCredentials;
use Webauthn\Signal\CurrentUserDetails;
use Webauthn\Signal\Signal;
use Webauthn\Signal\UnknownCredential;

/**
 * JsonResponse helper that wraps an application payload alongside a top-level
 * `signals` envelope shaped for the Stimulus base controller to dispatch via
 * `PublicKeyCredential.signalXxx(...)`.
 *
 * Each Signal is normalised to its W3C `*Options` dictionary and tagged with
 * its `type` so the JS side can route to the correct method:
 *
 * ```json
 * {
 *     "your": "payload",
 *     "signals": [
 *         {"type": "allAcceptedCredentials", "options": { "rpId": "...", "userId": "...", "allAcceptedCredentialIds": [...] }},
 *         {"type": "currentUserDetails",     "options": { "rpId": "...", "userId": "...", "name": "...", "displayName": "..." }}
 *     ]
 * }
 * ```
 *
 * The application controls *when* to emit signals, typically from a custom
 * {@see \Webauthn\Bundle\Security\Handler\SuccessHandler}.
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-signal-methods
 */
final readonly class WebauthnSignalResponse
{
    public function __construct(
        private NormalizerInterface $normalizer,
    ) {
    }

    /**
     * @param array<string, mixed> $payload
     * @param list<Signal>         $signals
     */
    public function withSignals(array $payload, array $signals): JsonResponse
    {
        $payload['signals'] = array_map(
            fn (Signal $signal): array => [
                'type' => $this->typeOf($signal),
                'options' => $this->normalizer->normalize($signal, 'json', [
                    AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                ]),
            ],
            $signals,
        );

        return new JsonResponse($payload);
    }

    private function typeOf(Signal $signal): string
    {
        return match ($signal::class) {
            UnknownCredential::class => 'unknownCredential',
            AllAcceptedCredentials::class => 'allAcceptedCredentials',
            CurrentUserDetails::class => 'currentUserDetails',
            default => throw new InvalidArgumentException(sprintf('Unsupported signal type "%s".', $signal::class)),
        };
    }
}
