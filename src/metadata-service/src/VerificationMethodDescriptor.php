<?php

declare(strict_types=1);

namespace Webauthn\MetadataService;

use function array_key_exists;
use Assert\Assertion;
use InvalidArgumentException;
use JsonSerializable;

class VerificationMethodDescriptor implements JsonSerializable
{
    public const USER_VERIFY_PRESENCE_INTERNAL = 'presence_internal';

    public const USER_VERIFY_FINGERPRINT_INTERNAL = 'fingerprint_internal';

    public const USER_VERIFY_PASSCODE_INTERNAL = 'passcode_internal';

    public const USER_VERIFY_VOICEPRINT_INTERNAL = 'voiceprint_internal';

    public const USER_VERIFY_FACEPRINT_INTERNAL = 'faceprint_internal';

    public const USER_VERIFY_LOCATION_INTERNAL = 'location_internal';

    public const USER_VERIFY_EYEPRINT_INTERNAL = 'eyeprint_internal';

    public const USER_VERIFY_PATTERN_INTERNAL = 'pattern_internal';

    public const USER_VERIFY_HANDPRINT_INTERNAL = 'handprint_internal';

    public const USER_VERIFY_PASSCODE_EXTERNAL = 'passcode_external';

    public const USER_VERIFY_PATTERN_EXTERNAL = 'pattern_external';

    public const USER_VERIFY_NONE = 'none';

    public const USER_VERIFY_ALL = 'all';

    private const OLD_USER_VERIFY_PRESENCE = 0x00000001;

    private const OLD_USER_VERIFY_FINGERPRINT = 0x00000002;

    private const OLD_USER_VERIFY_PASSCODE = 0x00000004;

    private const OLD_USER_VERIFY_VOICEPRINT = 0x00000008;

    private const OLD_USER_VERIFY_FACEPRINT = 0x00000010;

    private const OLD_USER_VERIFY_LOCATION = 0x00000020;

    private const OLD_USER_VERIFY_EYEPRINT = 0x00000040;

    private const OLD_USER_VERIFY_PATTERN = 0x00000080;

    private const OLD_USER_VERIFY_HANDPRINT = 0x00000100;

    private const OLD_USER_VERIFY_NONE = 0x00000200;

    private const OLD_USER_VERIFY_ALL = 0x00000400;

    private string $userVerificationMethod;

    public function __construct(
        string $userVerificationMethod,
        private ?CodeAccuracyDescriptor $caDesc = null,
        private ?BiometricAccuracyDescriptor $baDesc = null,
        private ?PatternAccuracyDescriptor $paDesc = null
    ) {
        Assertion::greaterOrEqualThan(
            $userVerificationMethod,
            0,
            Utils::logicException('The parameter "userVerificationMethod" is invalid')
        );
        $this->userVerificationMethod = $userVerificationMethod;
    }

    public function getUserVerification(): string
    {
        return $this->userVerification;
    }

    public function userPresence(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PRESENCE_INTERNAL;
    }

    public function fingerprint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_FINGERPRINT_INTERNAL;
    }

    public function passcodeInternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PASSCODE_INTERNAL;
    }

    public function voicePrint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_VOICEPRINT_INTERNAL;
    }

    public function facePrint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_FACEPRINT_INTERNAL;
    }

    public function location(): bool
    {
        return $this->userVerification === self::USER_VERIFY_LOCATION_INTERNAL;
    }

    public function eyePrint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_EYEPRINT_INTERNAL;
    }

    public function patternInternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PATTERN_INTERNAL;
    }

    public function handprint(): bool
    {
        return $this->userVerification === self::USER_VERIFY_HANDPRINT_INTERNAL;
    }

    public function passcodeExternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PASSCODE_EXTERNAL;
    }

    public function patternExternal(): bool
    {
        return $this->userVerification === self::USER_VERIFY_PATTERN_EXTERNAL;
    }

    public function none(): bool
    {
        return $this->userVerification === self::USER_VERIFY_NONE;
    }

    public function all(): bool
    {
        return $this->userVerification === self::USER_VERIFY_ALL;
    }

    public function getCaDesc(): ?CodeAccuracyDescriptor
    {
        return $this->caDesc;
    }

    public function getBaDesc(): ?BiometricAccuracyDescriptor
    {
        return $this->baDesc;
    }

    public function getPaDesc(): ?PatternAccuracyDescriptor
    {
        return $this->paDesc;
    }

    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        Assertion::true(
            array_key_exists('userVerificationMethod', $data) || array_key_exists('userVerification', $data),
            'The parameters "userVerificationMethod" and "userVerification" or are missing'
        );

        foreach (['caDesc', 'baDesc', 'paDesc'] as $key) {
            if (isset($data[$key])) {
                Assertion::isArray($data[$key], Utils::logicException(sprintf('Invalid parameter "%s"', $key)));
            }
        }

        $caDesc = isset($data['caDesc']) ? CodeAccuracyDescriptor::createFromArray($data['caDesc']) : null;
        $baDesc = isset($data['baDesc']) ? BiometricAccuracyDescriptor::createFromArray($data['baDesc']) : null;
        $paDesc = isset($data['paDesc']) ? PatternAccuracyDescriptor::createFromArray($data['paDesc']) : null;

        if (array_key_exists('userVerificationMethod', $data)) {
            Assertion::string(
                $data['userVerificationMethod'],
                Utils::logicException('The parameter "userVerificationMethod" is invalid')
            );

            return new self($data['userVerificationMethod'], $caDesc, $baDesc, $paDesc);
        }
        if (array_key_exists('userVerification', $data)) {
            Assertion::integer(
                $data['userVerification'],
                Utils::logicException('The parameter "userVerification" is invalid')
            );

            return new self(self::getVerificationMethod($data['userVerification']), $caDesc, $baDesc, $paDesc);
        }

        throw new InvalidArgumentException('Either "userVerificationMethod" or "userVerification" shall be present');
    }

    public function jsonSerialize(): array
    {
        $data = [
            'userVerificationMethod' => $this->userVerificationMethod,
            'caDesc' => $this->caDesc?->jsonSerialize(),
            'baDesc' => $this->baDesc?->jsonSerialize(),
            'paDesc' => $this->paDesc?->jsonSerialize(),
        ];

        return Utils::filterNullValues($data);
    }

    private static function getVerificationMethod(int $method): string
    {
        return match ($method) {
            self::OLD_USER_VERIFY_PRESENCE => self::USER_VERIFY_PRESENCE_INTERNAL,
            self::OLD_USER_VERIFY_FINGERPRINT => self::USER_VERIFY_FINGERPRINT_INTERNAL,
            self::OLD_USER_VERIFY_PASSCODE => self::USER_VERIFY_PASSCODE_INTERNAL,
            self::OLD_USER_VERIFY_VOICEPRINT => self::USER_VERIFY_VOICEPRINT_INTERNAL,
            self::OLD_USER_VERIFY_FACEPRINT => self::USER_VERIFY_FACEPRINT_INTERNAL,
            self::OLD_USER_VERIFY_LOCATION => self::USER_VERIFY_LOCATION_INTERNAL,
            self::OLD_USER_VERIFY_EYEPRINT => self::USER_VERIFY_EYEPRINT_INTERNAL,
            self::OLD_USER_VERIFY_PATTERN => self::USER_VERIFY_PATTERN_INTERNAL,
            self::OLD_USER_VERIFY_HANDPRINT => self::USER_VERIFY_HANDPRINT_INTERNAL,
            self::OLD_USER_VERIFY_ALL => self::USER_VERIFY_ALL,
            default => self::USER_VERIFY_NONE,
        };
    }
}
