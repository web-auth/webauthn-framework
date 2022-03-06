<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use Assert\Assertion;
use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\TokenBinding\TokenBinding;

class CollectedClientData
{
    /**
     * @var mixed[]
     */
    private array $data;

    private string $type;

    private string $challenge;

    private string $origin;

    /**
     * @var mixed[]|null
     */
    private ?array $tokenBinding;

    /**
     * @param mixed[] $data
     */
    public function __construct(
        private string $rawData,
        array $data
    ) {
        $this->type = $this->findData($data, 'type');
        $this->challenge = $this->findData($data, 'challenge', true, true);
        $this->origin = $this->findData($data, 'origin');
        $this->tokenBinding = $this->findData($data, 'tokenBinding', false);
        $this->data = $data;
    }

    public static function createFormJson(string $data): self
    {
        $rawData = Base64UrlSafe::decode($data);
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

    /**
     * @param mixed[] $json
     *
     * @return mixed|null
     */
    private function findData(array $json, string $key, bool $isRequired = true, bool $isB64 = false): mixed
    {
        if (! array_key_exists($key, $json)) {
            if ($isRequired) {
                throw new InvalidArgumentException(sprintf('The key "%s" is missing', $key));
            }

            return null;
        }

        return $isB64 ? Base64UrlSafe::decode($json[$key]) : $json[$key];
    }
}
