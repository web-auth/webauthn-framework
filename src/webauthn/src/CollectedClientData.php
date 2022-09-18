<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use InvalidArgumentException;
use function is_array;
use function is_string;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\TokenBinding\TokenBinding;

class CollectedClientData
{
    /**
     * @var mixed[]
     */
    private readonly array $data;

    private readonly string $type;

    private readonly string $challenge;

    private readonly string $origin;

    /**
     * @var mixed[]|null
     */
    private readonly ?array $tokenBinding;

    /**
     * @param mixed[] $data
     */
    public function __construct(
        private readonly string $rawData,
        array $data
    ) {
        $type = $data['type'] ?? '';
        (is_string($type) && $type !== '') || throw new InvalidArgumentException(
            'Invalid parameter "type". Shall be a non-empty string.'
        );
        $this->type = $type;

        $challenge = $data['challenge'] ?? '';
        is_string($challenge) || throw new InvalidArgumentException(
            'Invalid parameter "challenge". Shall be a string.'
        );
        $challenge = Base64UrlSafe::decodeNoPadding($challenge);
        $challenge !== '' || throw new InvalidArgumentException('Invalid parameter "challenge". Shall not be empty.');
        $this->challenge = $challenge;

        $origin = $data['origin'] ?? '';
        (is_string($origin) && $origin !== '') || throw new InvalidArgumentException(
            'Invalid parameter "origin". Shall be a non-empty string.'
        );
        $this->origin = $origin;

        $tokenBinding = $data['tokenBinding'] ?? null;
        $tokenBinding === null || is_array($tokenBinding) || throw new InvalidArgumentException(
            'Invalid parameter "tokenBinding". Shall be an object or .'
        );
        $this->tokenBinding = $tokenBinding;

        $this->data = $data;
    }

    public static function createFormJson(string $data): self
    {
        $rawData = Base64UrlSafe::decodeNoPadding($data);
        $json = json_decode($rawData, true, 512, JSON_THROW_ON_ERROR);

        return new self($rawData, $json);
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getChallenge(): string
    {
        return $this->challenge;
    }

    public function getOrigin(): string
    {
        return $this->origin;
    }

    public function getTokenBinding(): ?TokenBinding
    {
        return $this->tokenBinding === null ? null : TokenBinding::createFormArray($this->tokenBinding);
    }

    public function getRawData(): string
    {
        return $this->rawData;
    }

    /**
     * @return string[]
     */
    public function all(): array
    {
        return array_keys($this->data);
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    public function get(string $key): mixed
    {
        if (! $this->has($key)) {
            throw new InvalidArgumentException(sprintf('The key "%s" is missing', $key));
        }

        return $this->data[$key];
    }
}
