<?php

declare(strict_types=1);

namespace Webauthn;

use function array_key_exists;
use Assert\Assertion;
use InvalidArgumentException;
use const JSON_THROW_ON_ERROR;
use Throwable;
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
        $this->type = $this->findData(
            $data,
            'type',
            static function ($d): void {
                Assertion::string($d, 'Invalid parameter "type". Shall be a string.');
                Assertion::notEmpty($d, 'Invalid parameter "type". Shall not be empty.');
            }
        );
        $this->challenge = $this->findData(
            $data,
            'challenge',
            static function ($d): void {
                Assertion::string($d, 'Invalid parameter "challenge". Shall be a string.');
                Assertion::notEmpty($d, 'Invalid parameter "challenge". Shall not be empty.');
            },
            true,
            true
        );
        $this->origin = $this->findData(
            $data,
            'origin',
            static function ($d): void {
                Assertion::string($d, 'Invalid parameter "origin". Shall be a string.');
                Assertion::notEmpty($d, 'Invalid parameter "origin". Shall not be empty.');
            }
        );
        $this->tokenBinding = $this->findData(
            $data,
            'tokenBinding',
            static function ($d): void {
                Assertion::isArray($d, 'Invalid parameter "tokenBinding". Shall be an object.');
            },
            false
        );
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

    /**
     * @param mixed[] $json
     *
     * @return mixed|null
     */
    private function findData(
        array $json,
        string $key,
        callable $check,
        bool $isRequired = true,
        bool $isB64 = false
    ): mixed {
        if (! array_key_exists($key, $json)) {
            if ($isRequired) {
                throw new InvalidArgumentException(sprintf('The key "%s" is missing', $key));
            }

            return null;
        }

        $check($json[$key]);
        try {
            $data = $isB64 ? Base64::decodeUrlSafe($json[$key]) : $json[$key];
        } catch (Throwable $e) {
            throw new InvalidArgumentException(sprintf(
                'The parameter "%s" shall be Base64 Url Safe encoded',
                $key
            ), 0, $e);
        }

        return $data;
    }
}
