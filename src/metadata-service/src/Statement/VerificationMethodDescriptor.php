<?php

declare(strict_types=1);

namespace Webauthn\MetadataService\Statement;

use function array_key_exists;
use function is_array;
use JsonSerializable;
use Webauthn\MetadataService\Exception\MetadataStatementLoadingException;
use Webauthn\MetadataService\Utils;

/**
 * @final
 */
class VerificationMethodDescriptor implements JsonSerializable
{
    final public const USER_VERIFY_PRESENCE_INTERNAL = 'presence_internal';

    final public const USER_VERIFY_FINGERPRINT_INTERNAL = 'fingerprint_internal';

    final public const USER_VERIFY_PASSCODE_INTERNAL = 'passcode_internal';

    final public const USER_VERIFY_VOICEPRINT_INTERNAL = 'voiceprint_internal';

    final public const USER_VERIFY_FACEPRINT_INTERNAL = 'faceprint_internal';

    final public const USER_VERIFY_LOCATION_INTERNAL = 'location_internal';

    final public const USER_VERIFY_EYEPRINT_INTERNAL = 'eyeprint_internal';

    final public const USER_VERIFY_PATTERN_INTERNAL = 'pattern_internal';

    final public const USER_VERIFY_HANDPRINT_INTERNAL = 'handprint_internal';

    final public const USER_VERIFY_PASSCODE_EXTERNAL = 'passcode_external';

    final public const USER_VERIFY_PATTERN_EXTERNAL = 'pattern_external';

    final public const USER_VERIFY_NONE = 'none';

    final public const USER_VERIFY_ALL = 'all';

    private readonly string $userVerificationMethod;

    public function __construct(
        string $userVerificationMethod,
        private readonly ?CodeAccuracyDescriptor $caDesc = null,
        private readonly ?BiometricAccuracyDescriptor $baDesc = null,
        private readonly ?PatternAccuracyDescriptor $paDesc = null
    ) {
        $userVerificationMethod >= 0 || throw MetadataStatementLoadingException::create(
            'The parameter "userVerificationMethod" is invalid'
        );
        $this->userVerificationMethod = $userVerificationMethod;
    }

    public function getUserVerificationMethod(): string
    {
        return $this->userVerificationMethod;
    }

    public function userPresence(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_PRESENCE_INTERNAL;
    }

    public function fingerprint(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_FINGERPRINT_INTERNAL;
    }

    public function passcodeInternal(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_PASSCODE_INTERNAL;
    }

    public function voicePrint(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_VOICEPRINT_INTERNAL;
    }

    public function facePrint(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_FACEPRINT_INTERNAL;
    }

    public function location(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_LOCATION_INTERNAL;
    }

    public function eyePrint(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_EYEPRINT_INTERNAL;
    }

    public function patternInternal(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_PATTERN_INTERNAL;
    }

    public function handprint(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_HANDPRINT_INTERNAL;
    }

    public function passcodeExternal(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_PASSCODE_EXTERNAL;
    }

    public function patternExternal(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_PATTERN_EXTERNAL;
    }

    public function none(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_NONE;
    }

    public function all(): bool
    {
        return $this->userVerificationMethod === self::USER_VERIFY_ALL;
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

    /**
     * @param array<string, mixed> $data
     */
    public static function createFromArray(array $data): self
    {
        $data = Utils::filterNullValues($data);
        if (isset($data['userVerification']) && ! isset($data['userVerificationMethod'])) {
            $data['userVerificationMethod'] = $data['userVerification'];
            unset($data['userVerification']);
        }
        array_key_exists('userVerificationMethod', $data) || throw MetadataStatementLoadingException::create(
            'The parameters "userVerificationMethod" is missing'
        );

        foreach (['caDesc', 'baDesc', 'paDesc'] as $key) {
            if (isset($data[$key])) {
                is_array($data[$key]) || throw MetadataStatementLoadingException::create(
                    sprintf('Invalid parameter "%s"', $key)
                );
            }
        }

        $caDesc = isset($data['caDesc']) ? CodeAccuracyDescriptor::createFromArray($data['caDesc']) : null;
        $baDesc = isset($data['baDesc']) ? BiometricAccuracyDescriptor::createFromArray($data['baDesc']) : null;
        $paDesc = isset($data['paDesc']) ? PatternAccuracyDescriptor::createFromArray($data['paDesc']) : null;

        return new self($data['userVerificationMethod'], $caDesc, $baDesc, $paDesc);
    }

    /**
     * @return array<string, mixed>
     */
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
}
