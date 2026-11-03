<?php

declare(strict_types=1);

namespace Webauthn\Util;

use function count;
use function in_array;
use function is_array;
use function strlen;

/**
 * Helper around the Related Origin Requests anti-tracking mitigation defined by WebAuthn Level 3.
 *
 * A client resolving `/.well-known/webauthn` walks the published origins and keeps track of the distinct eTLD+1 labels
 * it has seen so far: the label immediately preceding the public suffix of the origin's host, so that
 * "https://example.com" and "https://example.co.uk" both yield "example" and count as a single label. Once five
 * distinct labels have been collected, every remaining origin introducing a new label is skipped, which makes it
 * unusable as a related origin even though the relying party published it.
 *
 * The limit therefore constrains the number of registrable names, not the number of origins: a relying party may
 * publish as many origins as it wants as long as they resolve to at most five distinct labels.
 *
 * Deriving a label requires knowing the public suffix of a host, which is what the injected
 * {@see PublicSuffixResolver} is for. The library ships no public suffix data of its own.
 *
 * @see https://www.w3.org/TR/webauthn-3/#sctn-related-origins
 */
final readonly class RelatedOrigins
{
    /**
     * Maximum number of distinct eTLD+1 labels a client processes while resolving related origins.
     */
    public const MAX_DISTINCT_LABELS = 5;

    public function __construct(
        private PublicSuffixResolver $publicSuffixResolver
    ) {
    }

    public static function create(PublicSuffixResolver $publicSuffixResolver): self
    {
        return new self($publicSuffixResolver);
    }

    /**
     * Returns the eTLD+1 label of the given origin, or null when no label can be derived: non-URL facet identifiers
     * (e.g. "android:apk-key-hash:..."), IP literals and single-label hosts such as "localhost".
     */
    public function getLabel(string $origin): ?string
    {
        $host = self::extractHost($origin);
        if ($host === null) {
            return null;
        }

        $suffix = $this->publicSuffixResolver->getPublicSuffix($host);
        if ($suffix === null || ! str_ends_with($host, '.' . $suffix)) {
            return null;
        }

        $registrablePart = substr($host, 0, -(strlen($suffix) + 1));
        if ($registrablePart === '') {
            return null;
        }
        $labels = explode('.', $registrablePart);

        return $labels[count($labels) - 1];
    }

    /**
     * Returns the distinct eTLD+1 labels of the given origins, in the order a client would collect them.
     *
     * @param array<string> $origins
     *
     * @return list<string>
     */
    public function getDistinctLabels(array $origins): array
    {
        $labels = [];
        foreach ($origins as $origin) {
            $label = $this->getLabel($origin);
            if ($label === null || in_array($label, $labels, true)) {
                continue;
            }
            $labels[] = $label;
        }

        return $labels;
    }

    /**
     * @param array<string> $origins
     */
    public function exceedsLabelLimit(array $origins): bool
    {
        return count($this->getDistinctLabels($origins)) > self::MAX_DISTINCT_LABELS;
    }

    /**
     * Returns the origins a client would skip because they introduce a label beyond the fifth distinct one. Origins
     * without a derivable label are never reported here, even though a client ignores them as related origins too.
     *
     * @param array<string> $origins
     *
     * @return list<string>
     */
    public function getIgnoredOrigins(array $origins): array
    {
        $labels = [];
        $ignored = [];
        foreach ($origins as $origin) {
            $label = $this->getLabel($origin);
            if ($label === null || in_array($label, $labels, true)) {
                continue;
            }
            if (count($labels) === self::MAX_DISTINCT_LABELS) {
                $ignored[] = $origin;
                continue;
            }
            $labels[] = $label;
        }

        return $ignored;
    }

    private static function extractHost(string $origin): ?string
    {
        $parsed = parse_url($origin);
        if (! is_array($parsed)) {
            return null;
        }
        $host = $parsed['host'] ?? (isset($parsed['scheme']) ? null : $parsed['path'] ?? null);
        if ($host === null) {
            return null;
        }

        return rtrim(strtolower(trim($host, " \t\n\r\0\x0B[]")), '.');
    }
}
