<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace U2F\Tests\Unit;

use Base64Url\Base64Url;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use U2F\RegistrationRequest;
use U2F\RegistrationResponse;

/**
 * @group unit
 */
final class RegistrationResponseTest extends TestCase
{
    /**
     * @test
     */
    public function theRegistrationRequestContainsAnError(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'errorCode' => 1,
        ]);
    }

    /**
     * @test
     */
    public function thereIsNoClientData(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgDh1xe2NkrGHygQQsdbUbsIDo5rzK98uGFdtRnnkAcMECIAueb-X0G1j67XwU3JRd8_9bAJiFBnzTxvTWifRUtiUm',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
        ]);
    }

    /**
     * @test
     */
    public function theClientDataIsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgDh1xe2NkrGHygQQsdbUbsIDo5rzK98uGFdtRnnkAcMECIAueb-X0G1j67XwU3JRd8_9bAJiFBnzTxvTWifRUtiUm',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 123,
        ]);
    }

    /**
     * @test
     */
    public function theVersionIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgDh1xe2NkrGHygQQsdbUbsIDo5rzK98uGFdtRnnkAcMECIAueb-X0G1j67XwU3JRd8_9bAJiFBnzTxvTWifRUtiUm',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theVersionIsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgDh1xe2NkrGHygQQsdbUbsIDo5rzK98uGFdtRnnkAcMECIAueb-X0G1j67XwU3JRd8_9bAJiFBnzTxvTWifRUtiUm',
            'version' => 123,
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theVersionIsNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported protocol version.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgDh1xe2NkrGHygQQsdbUbsIDo5rzK98uGFdtRnnkAcMECIAueb-X0G1j67XwU3JRd8_9bAJiFBnzTxvTWifRUtiUm',
            'version' => 'U2F_V1',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theRegistrationDataIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theRegistrationDataIsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'registrationData' => 123,
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theTypeIsNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid response.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgDh1xe2NkrGHygQQsdbUbsIDo5rzK98uGFdtRnnkAcMECIAueb-X0G1j67XwU3JRd8_9bAJiFBnzTxvTWifRUtiUm',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJ1bnN1cHBvcnRlZC50eXBlIiwiY2hhbGxlbmdlIjoiM2xwM2xjdVlTSG8zeXJHZnVMdlE1TkVkLUxXRFRIUlZhRElLWGZCdmg4cyIsIm9yaWdpbiI6Imh0dHBzOi8vdHdvZmFjdG9yczo0MDQzIiwiY2lkX3B1YmtleSI6InVudXNlZCJ9',
        ]);
    }

    /**
     * @test
     */
    public function theReservedByteIsNotValid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad reserved byte.');
        new RegistrationResponse([
            'registrationData' => Base64Url::encode("\x00"),
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function thePublicKeyLengthIsNotValid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad public key length.');
        new RegistrationResponse([
            'registrationData' => Base64Url::encode("\x05-------"),
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theKeyHandleLengthOctetIsNotValid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key handle length.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theKeyHandleLengthIsNotValid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key handle length.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6AA',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theKeyHandleIsNotValid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad key handle.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFw',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theCertificateHeaderIsNotValid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad certificate header.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwgg',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function theCertificateIsNotValid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Bad certificate.');
        new RegistrationResponse([
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJp',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ]);
    }

    /**
     * @test
     */
    public function iCanLoadAValidRegistrationResponse(): void
    {
        $response = new RegistrationResponse(
            $this->getValidRegistrationResponse()
        );

        static::assertEquals('{"typ":"navigator.id.finishEnrollment","challenge":"3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s","origin":"https://twofactors:4043","cid_pubkey":"unused"}', $response->getClientData()->getRawData());
        static::assertEquals('navigator.id.finishEnrollment', $response->getClientData()->getType());
        static::assertEquals(Base64Url::decode('3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s'), $response->getClientData()->getChallenge());
        static::assertEquals('https://twofactors:4043', $response->getClientData()->getOrigin());
        static::assertEquals('unused', $response->getClientData()->getChannelIdPublicKey());

        static::assertEquals(Base64Url::decode('BFeWllSolex8diHswKHW6z7KmtrMypMnKNZehwDSP9RPn3GbMeB_WaRP0Ovzaca1g9ff3o-tRDHj_niFpNmjyDo'), $response->getRegisteredKey()->getPublicKey()->getValue());
        static::assertEquals('-----BEGIN CERTIFICATE-----'.PHP_EOL.
'MIICLTCCARegAwIBAgIEBbYFeTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXVi'.PHP_EOL.
'aWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAw'.PHP_EOL.
'WhgPMjA1MDA5MDQwMDAwMDBaMCgxJjAkBgNVBAMMHVl1YmljbyBVMkYgRUUgU2Vy'.PHP_EOL.
'aWFsIDk1ODE1MDMzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/bjes6HtcOtj'.PHP_EOL.
'bAZutgBplqX5cPy124j8OzBdQeWWbwwbVLhS/vCgkH7Rfzv/wp1NMhuc+KhKLOqg'.PHP_EOL.
'OMq9NdWY3qMmMCQwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEw'.PHP_EOL.
'CwYJKoZIhvcNAQELA4IBAQB+0/tszCUgE/gvIYwqN9pgMdIOfzCB2vyusSj8f5sj'.PHP_EOL.
'ORS/tk1hNfF84iH6dk9FPvEnOozpZZVkQrsvHkdIP3N9y8mLWFN3/vULJw4CifiE'.PHP_EOL.
'NvGtz0myYh7l4wLfVVuat0Jy4Gn5GBSbPexPEiKLEMD4jeNq9Yp0u0Qrha4AU2S9'.PHP_EOL.
'pnAgWPwfLYebUwER6mDobGPxf6WUTMg/CqJphIs+44imwJ5rBZU/y7j0foOifgBy'.PHP_EOL.
'pjwyrWSGTpJtcRL6GZf3g5ZW+7Mr6PeInQ8BRVGaJ6/djkawTKQpDYVAtjS4hhYe'.PHP_EOL.
'dYjIYpnc3WQ10WeKOm8KdIKcTdP3DDUk0d3xbXit0htk'.PHP_EOL.
'-----END CERTIFICATE-----'.PHP_EOL, $response->getRegisteredKey()->getAttestationCertificate());
        static::assertEquals(Base64Url::decode('Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ'), $response->getRegisteredKey()->getKeyHandler()->getValue());
        static::assertEquals('-----BEGIN PUBLIC KEY-----'.PHP_EOL.
'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV5aWVKiV7Hx2IezAodbrPsqa2szK'.PHP_EOL.
'kyco1l6HANI/1E+fcZsx4H9ZpE/Q6/NpxrWD19/ej61EMeP+eIWk2aPIOg=='.PHP_EOL.
'-----END PUBLIC KEY-----'.PHP_EOL, $response->getRegisteredKey()->getPublicKeyAsPem());
        static::assertEquals('U2F_V2', $response->getRegisteredKey()->getVersion());
        static::assertEquals('{"version":"U2F_V2","keyHandle":"Ws1pyRaocwNNxYIXIHttjOO1628kVQ2EK6EVVZ_wWKs089-rszT2fkSnSfm4V6wV9ryz2-K8Vm5Fs_r7ctAcoQ","publicKey":"BFeWllSolex8diHswKHW6z7KmtrMypMnKNZehwDSP9RPn3GbMeB_WaRP0Ovzaca1g9ff3o-tRDHj_niFpNmjyDo","attestationCertificate":"-----BEGIN CERTIFICATE-----\nMIICLTCCARegAwIBAgIEBbYFeTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXVi\naWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAw\nWhgPMjA1MDA5MDQwMDAwMDBaMCgxJjAkBgNVBAMMHVl1YmljbyBVMkYgRUUgU2Vy\naWFsIDk1ODE1MDMzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\/bjes6HtcOtj\nbAZutgBplqX5cPy124j8OzBdQeWWbwwbVLhS\/vCgkH7Rfzv\/wp1NMhuc+KhKLOqg\nOMq9NdWY3qMmMCQwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEw\nCwYJKoZIhvcNAQELA4IBAQB+0\/tszCUgE\/gvIYwqN9pgMdIOfzCB2vyusSj8f5sj\nORS\/tk1hNfF84iH6dk9FPvEnOozpZZVkQrsvHkdIP3N9y8mLWFN3\/vULJw4CifiE\nNvGtz0myYh7l4wLfVVuat0Jy4Gn5GBSbPexPEiKLEMD4jeNq9Yp0u0Qrha4AU2S9\npnAgWPwfLYebUwER6mDobGPxf6WUTMg\/CqJphIs+44imwJ5rBZU\/y7j0foOifgBy\npjwyrWSGTpJtcRL6GZf3g5ZW+7Mr6PeInQ8BRVGaJ6\/djkawTKQpDYVAtjS4hhYe\ndYjIYpnc3WQ10WeKOm8KdIKcTdP3DDUk0d3xbXit0htk\n-----END CERTIFICATE-----\n"}', json_encode($response->getRegisteredKey()));

        static::assertEquals(Base64Url::decode('MEQCIA4dcXtjZKxh8oEELHW1G7CA6Oa8yvfLhhXbUZ55AHDBAiALnm_l9BtY-u18FNyUXfP_WwCYhQZ808b01on0VLYlJg'), $response->getSignature());

        $request = $this->prophesize(RegistrationRequest::class);
        $request->getChallenge()->willReturn(Base64Url::decode('3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s'));
        $request->getApplicationId()->willReturn('https://twofactors:4043');
        static::assertTrue($response->isValid($request->reveal()));
    }

    /**
     * @test
     */
    public function theChallengeInTheRequestDoesNotMatchTheChallengeInTheClientData(): void
    {
        $response = new RegistrationResponse(
            $this->getValidRegistrationResponse()
        );
        $request = $this->prophesize(RegistrationRequest::class);
        $request->getChallenge()->willReturn('foo');
        $request->getApplicationId()->willReturn('https://twofactors:4043');

        static::assertFalse($response->isValid($request->reveal()));
    }

    /**
     * @test
     */
    public function theApplicationIdInTheRequestDoesNotMatchTheApplicationIdInTheClientData(): void
    {
        $response = new RegistrationResponse(
            $this->getValidRegistrationResponse()
        );
        $request = $this->prophesize(RegistrationRequest::class);
        $request->getChallenge()->willReturn(Base64Url::decode('3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s'));
        $request->getApplicationId()->willReturn('https://no-factors:443');

        static::assertFalse($response->isValid($request->reveal()));
    }

    private function getValidRegistrationResponse(): array
    {
        return [
            'registrationData' => 'BQRXlpZUqJXsfHYh7MCh1us-yprazMqTJyjWXocA0j_UT59xmzHgf1mkT9Dr82nGtYPX396PrUQx4_54haTZo8g6QFrNackWqHMDTcWCFyB7bYzjtetvJFUNhCuhFVWf8FirNPPfq7M09n5Ep0n5uFesFfa8s9vivFZuRbP6-3LQHKEwggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRAIgDh1xe2NkrGHygQQsdbUbsIDo5rzK98uGFdtRnnkAcMECIAueb-X0G1j67XwU3JRd8_9bAJiFBnzTxvTWifRUtiUm',
            'version' => 'U2F_V2',
            'challenge' => '3lp3lcuYSHo3yrGfuLvQ5NEd-LWDTHRVaDIKXfBvh8s',
            'clientData' => 'eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IjNscDNsY3VZU0hvM3lyR2Z1THZRNU5FZC1MV0RUSFJWYURJS1hmQnZoOHMiLCJvcmlnaW4iOiJodHRwczovL3R3b2ZhY3RvcnM6NDA0MyIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ',
        ];
    }
}
