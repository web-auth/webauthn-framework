<?php

declare(strict_types=1);

/**
 * Merchant backend (port 8003). Sits between the merchant frontend (the
 * shopper's browser) and the bank/ACS (port 8001). The browser never talks
 * to the bank directly — every WebAuthn artefact flows through this back
 * channel.
 *
 *   Browser (merchant-front, 8002)
 *      │  POST /api/payment/options    (CORS)
 *      │  POST /api/payment/submit     (CORS)
 *      │  GET  /api/payment/status     (CORS, polled)
 *      ▼
 *   Merchant backend (this file, 8003)
 *      │  HTTPS server-to-server (no CORS — pure curl)
 *      ▼
 *   Bank / ACS (8001)
 *
 * Async behaviour: /api/payment/submit stores the assertion as PENDING and
 * returns immediately. The bank ACS round-trip happens lazily on the
 * /api/payment/status poll, two seconds after submission, to simulate a
 * real back-channel latency that a worker / webhook would absorb.
 *
 * Run with:  php -S localhost:8003 -t . router.php
 */

$_ENV['VAR_DIR'] ??= __DIR__ . '/../var';

use App\SpcDemo\TransactionStore;

require_once __DIR__ . '/../../src/bootstrap.php';
require_once __DIR__ . '/../../src/CredentialStore.php';
require_once __DIR__ . '/../../src/ChallengeStore.php';
require_once __DIR__ . '/../../src/TransactionStore.php';

const BANK_BASE = 'http://localhost:8001';
const FRONT_ORIGIN = 'http://localhost:8002';
const BACK_CHANNEL_DELAY_SECONDS = 2;

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (! str_starts_with($path, '/api/')) {
    http_response_code(404);
    echo 'Not found';
    return true;
}

// CORS for the merchant frontend.
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin === FRONT_ORIGIN) {
    header('Access-Control-Allow-Origin: ' . FRONT_ORIGIN);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        http_response_code(204);
        return true;
    }
}

header('Content-Type: application/json');

$store = new TransactionStore(($_ENV['VAR_DIR']) . '/transactions.json');

try {
    match ($path) {
        '/api/payment/options' => paymentOptions(),
        '/api/payment/submit' => paymentSubmit($store),
        '/api/payment/status' => paymentStatus($store),
        default => notFound(),
    };
} catch (\Throwable $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage(), 'class' => $e::class], JSON_THROW_ON_ERROR);
}

function notFound(): void
{
    http_response_code(404);
    echo json_encode(['error' => 'Not found'], JSON_THROW_ON_ERROR);
}

/**
 * @return array<string, mixed>
 */
function readJson(): array
{
    $body = file_get_contents('php://input') ?: '{}';
    $json = json_decode($body, true, flags: JSON_THROW_ON_ERROR);

    return is_array($json) ? $json : [];
}

/**
 * Server-to-server POST to the bank.
 *
 * @return array{status: int, body: string, json: array<string, mixed>}
 */
function postToBank(string $endpoint, string $jsonBody): array
{
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => $jsonBody,
            'ignore_errors' => true,
        ],
    ]);
    $body = (string) file_get_contents(BANK_BASE . $endpoint, false, $ctx);
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $m)) {
        $status = (int) $m[1];
    }
    $json = json_decode($body, true);

    return [
        'status' => $status,
        'body' => $body,
        'json' => is_array($json) ? $json : [],
    ];
}

function paymentOptions(): void
{
    $body = readJson();
    $relay = postToBank('/api/payment/options', json_encode($body, \JSON_THROW_ON_ERROR));
    if ($relay['status'] >= 400) {
        http_response_code($relay['status']);
        echo $relay['body'];
        return;
    }
    echo $relay['body'];
}

function paymentSubmit(TransactionStore $store): void
{
    $body = readJson();
    $transactionId = (string) ($body['transactionId'] ?? '');
    $credential = $body['credential'] ?? null;
    if ($transactionId === '' || ! is_array($credential)) {
        http_response_code(400);
        echo json_encode(['error' => 'transactionId + credential are required.'], \JSON_THROW_ON_ERROR);
        return;
    }

    // Park the assertion. Reply immediately — the actual bank hop is lazy.
    $store->submit($transactionId, $credential);

    echo json_encode([
        'transactionId' => $transactionId,
        'status' => TransactionStore::STATUS_PENDING,
        'message' => 'Captured. Poll /api/payment/status?txn=' . urlencode($transactionId),
        'pollEverySeconds' => 1,
    ], \JSON_THROW_ON_ERROR);
}

function paymentStatus(TransactionStore $store): void
{
    $transactionId = (string) ($_GET['txn'] ?? '');
    if ($transactionId === '') {
        http_response_code(400);
        echo json_encode(['error' => 'txn query string is required.'], \JSON_THROW_ON_ERROR);
        return;
    }

    $row = $store->get($transactionId);
    if ($row === null) {
        http_response_code(404);
        echo json_encode(['error' => 'Unknown transaction.'], \JSON_THROW_ON_ERROR);
        return;
    }

    // Lazy back-channel: if still pending and enough time has elapsed,
    // call the bank now and update the store.
    if ($row['status'] === TransactionStore::STATUS_PENDING
        && (time() - $row['submittedAt']) >= BACK_CHANNEL_DELAY_SECONDS
    ) {
        $relay = postToBank('/api/acs/verify', json_encode($row['assertion'], \JSON_THROW_ON_ERROR));
        if ($relay['status'] === 200 && ($relay['json']['transStatus'] ?? null) === 'Y') {
            $store->approve($transactionId, $relay['json']);
        } else {
            $reason = $relay['json']['error'] ?? sprintf('Bank returned HTTP %d', $relay['status']);
            $store->decline($transactionId, $reason);
        }
        $row = $store->get($transactionId);
        \assert($row !== null);
    }

    echo json_encode([
        'transactionId' => $transactionId,
        'status' => $row['status'],
        'bankResponse' => $row['bankResponse'],
        'error' => $row['error'],
    ], \JSON_THROW_ON_ERROR);
}
