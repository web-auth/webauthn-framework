<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Webauthn\TrustPath;

class CertificateTrustPath implements TrustPath
{
    /**
     * @var string[]
     */
    private $certificates;

    /**
     * @param string[] $certificates
     */
    public function __construct(array $certificates)
    {
        $this->certificates = $certificates;
    }

    /**
     * @return string[]
     */
    public function getCertificates(): array
    {
        return $this->certificates;
    }
}
