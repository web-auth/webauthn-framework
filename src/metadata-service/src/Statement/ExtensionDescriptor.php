<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use Assert\Assertion;
use JsonSerializable;
use Webauthn\MetadataService\Utils;

class ExtensionDescriptor implements JsonSerializable
{
    private readonly ?int $tag;

    public function __construct(
        private readonly string $id,
        ?int $tag,
        private readonly ?string $data,
        private readonly bool $failIfUnknown
    ) {
        if ($tag !== null) {
            Assertion::greaterOrEqualThan($tag, 0, 'Invalid data. The parameter "tag" shall be a positive integer');
        }
        $this->tag = $tag;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getTag(): ?int
    {
        return $this->tag;
    }

    public function getData(): ?string
    {
        return $this->data;
    }

    public function isFailIfUnknown(): bool
    {
        return $this->failIfUnknown;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        Assertion::keyExists($data, 'id', 'Invalid data. The parameter "id" is missing');
        Assertion::string($data['id'], 'Invalid data. The parameter "id" shall be a string');
        Assertion::keyExists($data, 'fail_if_unknown', 'Invalid data. The parameter "fail_if_unknown" is missing');
        Assertion::boolean(
            $data['fail_if_unknown'],
            'Invalid data. The parameter "fail_if_unknown" shall be a boolean'
        );
        if (array_key_exists('tag', $data)) {
            Assertion::integer($data['tag'], 'Invalid data. The parameter "tag" shall be a positive integer');
        }
        if (array_key_exists('data', $data)) {
            Assertion::string($data['data'], 'Invalid data. The parameter "data" shall be a string');
        }

        return new self($data['id'], $data['tag'] ?? null, $data['data'] ?? null, $data['fail_if_unknown']);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $result = [
            'id' => $this->id,
            'tag' => $this->tag,
            'data' => $this->data,
            'fail_if_unknown' => $this->failIfUnknown,
        ];

        return Utils::filterNullValues($result);
    }
}
