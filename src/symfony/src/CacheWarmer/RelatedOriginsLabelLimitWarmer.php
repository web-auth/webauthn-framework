<?php

declare(strict_types=1);

namespace Webauthn\Bundle\CacheWarmer;

use function count;
use function implode;
use Psr\Log\LoggerInterface;
use function sprintf;
use Symfony\Component\HttpKernel\CacheWarmer\CacheWarmerInterface;
use Webauthn\Util\PublicSuffixResolver;
use Webauthn\Util\RelatedOrigins;

/**
 * Related Origin Requests are capped by the client to 5 distinct eTLD+1 labels as an anti-tracking mitigation. Every
 * origin published by "/.well-known/webauthn" that introduces a label beyond that cap is silently ignored, so the
 * relying party ends up advertising origins that can never be used.
 *
 * The check runs when the cache is warmed up rather than when the container is compiled, because deriving a label
 * needs the application-provided {@see PublicSuffixResolver} service. It warns and never fails: rejecting a
 * configuration that used to boot would break existing applications.
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-related-origins
 */
final readonly class RelatedOriginsLabelLimitWarmer implements CacheWarmerInterface
{
    /**
     * @param array<string> $allowedOrigins
     */
    public function __construct(
        private array $allowedOrigins,
        private PublicSuffixResolver $publicSuffixResolver,
        private LoggerInterface $logger,
    ) {
    }

    public function isOptional(): bool
    {
        return true;
    }

    /**
     * @return array<string>
     */
    public function warmUp(string $cacheDir, ?string $buildDir = null): array
    {
        $relatedOrigins = RelatedOrigins::create($this->publicSuffixResolver);
        $ignoredOrigins = $relatedOrigins->getIgnoredOrigins($this->allowedOrigins);
        if (count($ignoredOrigins) === 0) {
            return [];
        }

        $this->logger->warning(sprintf(
            'The "/.well-known/webauthn" endpoint advertises %d distinct eTLD+1 labels while clients only process %d of them (WebAuthn Level 3, Related Origin Requests). The following origins will be ignored: %s. Reduce the number of registrable domains in "webauthn.allowed_origins" or set "webauthn.related_origins.label_limit_check" to false to silence this warning.',
            count($relatedOrigins->getDistinctLabels($this->allowedOrigins)),
            RelatedOrigins::MAX_DISTINCT_LABELS,
            implode(', ', $ignoredOrigins)
        ));

        return [];
    }
}
