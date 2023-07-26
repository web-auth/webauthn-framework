<?php

declare(strict_types=1);

namespace Webauthn\AuthenticationExtensions\Uvm;

use Webauthn\AuthenticationExtensions\ExtensionOutput;

final class UvmExtensionOutput implements ExtensionOutput
{
    /**
     * @param UvmEntry[] $entries
     */
    private function __construct(
        private readonly array $entries
    ) {
    }

    public static function create(array $data)
    {
        $entries = array_reduce(
            $data,
            static function (array $carry, array $entry): array {
                $carry[] = UvmEntry::create(
                    (int) $entry[0],
                    (int) $entry[1],
                    (int) $entry[2],
                );

                return $carry;
            },
            [],
        );

        return new self($entries);
    }

    /**
     * @return UvmEntry[]
     */
    public function getEntries(): array
    {
        return $this->entries;
    }

    public function identifier(): string
    {
        return 'uvm';
    }
}
