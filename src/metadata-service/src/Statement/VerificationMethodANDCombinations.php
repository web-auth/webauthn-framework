<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use JsonSerializable;

/**
 * @final
 */
class VerificationMethodANDCombinations implements JsonSerializable
{
    /**
     * @param VerificationMethodDescriptor[] $verificationMethods
     */
    public function __construct(
        public array $verificationMethods = []
    ) {
    }

    /**
     * @param VerificationMethodDescriptor[] $verificationMethods
     */
    public static function create(array $verificationMethods): self
    {
        return new self($verificationMethods);
    }

    /**
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function addVerificationMethodDescriptor(VerificationMethodDescriptor $verificationMethodDescriptor): self
    {
        $this->verificationMethods[] = $verificationMethodDescriptor;

        return $this;
    }

    /**
     * @return VerificationMethodDescriptor[]
     * @deprecated since 4.7.0. Please use the property directly.
     */
    public function getVerificationMethods(): array
    {
        return $this->verificationMethods;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        return self::create(
            array_map(
                static fn (array $datum): VerificationMethodDescriptor => VerificationMethodDescriptor::createFromArray(
                    $datum
                ),
                $data
            )
        );
    }

    /**
     * @return array<array<mixed>>
     */
    public function jsonSerialize(): array
    {
        return array_map(
            static fn (VerificationMethodDescriptor $object): array => $object->jsonSerialize(),
            $this->verificationMethods
        );
    }
}
