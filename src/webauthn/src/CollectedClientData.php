<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use Assert\Assertion;
use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use Webauthn\TokenBinding\TokenBinding;
use Webauthn\Util\Base64;

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
        Assertion::string($type, 'Invalid parameter "type". Shall be a string.');
        Assertion::notEmpty($type, 'Invalid parameter "type". Shall not be empty.');
        $this->type = $type;

        $challenge = $data['challenge'] ?? '';
        Assertion::string($challenge, 'Invalid parameter "challenge". Shall be a string.');
        $challenge = Base64::decodeUrlSafe($challenge);
        $this->challenge = $challenge;
        Assertion::notEmpty($challenge, 'Invalid parameter "challenge". Shall not be empty.');

        $origin = $data['origin'] ?? '';
        Assertion::string($origin, 'Invalid parameter "origin". Shall be a string.');
        Assertion::notEmpty($origin, 'Invalid parameter "origin". Shall not be empty.');
        $this->origin = $origin;

        $tokenBinding = $data['tokenBinding'] ?? null;
        Assertion::nullOrIsArray($tokenBinding, 'Invalid parameter "tokenBinding". Shall be an object or .');
        $this->tokenBinding = $tokenBinding;

        $this->data = $data;
    }

    public static function createFormJson(string $data): self
    {
        $rawData = Base64::decodeUrlSafe($data);
        $json = json_decode($rawData, true, 512, JSON_THROW_ON_ERROR);
        Assertion::isArray($json, 'Invalid collected client data');

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
