<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$baseDir = __DIR__;
$uploadDir = $baseDir . DIRECTORY_SEPARATOR . 'uploads';
$manifestPath = $baseDir . DIRECTORY_SEPARATOR . 'uploaded_manifest.json';

if (!is_dir($uploadDir) && !mkdir($uploadDir, 0775, true) && !is_dir($uploadDir)) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Could not create upload directory.']);
    exit;
}

function slugify(string $name): string {
    $name = strtolower(preg_replace('/\.csv$/i', '', $name));
    $name = preg_replace('/[^a-z0-9]+/', '-', $name);
    $name = trim((string) $name, '-');
    return substr($name !== '' ? $name : 'tenant', 0, 64);
}

function parse_points_ratio(string $value, string $status): float {
    if (preg_match('/([0-9.]+)\s*\/\s*([0-9.]+)/', $value, $m)) {
        $achieved = (float) $m[1];
        $total = (float) $m[2];
        return $total > 0 ? max(0.0, min(1.0, $achieved / $total)) : 0.0;
    }
    $status = strtolower($status);
    if (str_contains($status, 'complete') || str_contains($status, 'resolved') || str_contains($status, 'done')) {
        return 1.0;
    }
    if (str_contains($status, 'planned') || str_contains($status, 'third') || str_contains($status, 'alternative')) {
        return 0.45;
    }
    return 0.0;
}

function summarize_csv(string $path): array {
    $handle = fopen($path, 'rb');
    if (!$handle) {
        return ['score' => 0, 'controls' => 0, 'complete' => 0, 'partial' => 0, 'failed' => 0];
    }
    $headers = fgetcsv($handle);
    if (!is_array($headers)) {
        fclose($handle);
        return ['score' => 0, 'controls' => 0, 'complete' => 0, 'partial' => 0, 'failed' => 0];
    }
    $headers = array_map(static fn($h) => strtolower(trim((string) $h)), $headers);
    $pointsIndex = array_search('points achieved', $headers, true);
    if ($pointsIndex === false) {
        $pointsIndex = array_search('points', $headers, true);
    }
    $statusIndex = array_search('status', $headers, true);

    $count = 0;
    $scoreSum = 0.0;
    $complete = 0;
    $partial = 0;
    $failed = 0;

    while (($row = fgetcsv($handle)) !== false) {
        $points = $pointsIndex !== false ? (string) ($row[$pointsIndex] ?? '') : '';
        $status = $statusIndex !== false ? (string) ($row[$statusIndex] ?? '') : '';
        $score = (int) round(parse_points_ratio($points, $status) * 100);
        $scoreSum += $score;
        $count++;
        if ($score >= 80) {
            $complete++;
        } elseif ($score >= 40) {
            $partial++;
        } else {
            $failed++;
        }
    }
    fclose($handle);

    return [
        'score' => $count > 0 ? (int) round($scoreSum / $count) : 0,
        'controls' => $count,
        'complete' => $complete,
        'partial' => $partial,
        'failed' => $failed,
    ];
}

function read_uploaded_manifest(string $path): array {
    if (!is_file($path)) {
        return [];
    }
    $json = json_decode((string) file_get_contents($path), true);
    return is_array($json) && isset($json['tenants']) && is_array($json['tenants'])
        ? $json['tenants']
        : [];
}

$files = $_FILES['csv'] ?? null;
if (!$files || !isset($files['name'])) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'No CSV files uploaded.']);
    exit;
}

$normalized = [];
if (is_array($files['name'])) {
    foreach ($files['name'] as $idx => $name) {
        $normalized[] = [
            'name' => (string) $name,
            'tmp_name' => (string) ($files['tmp_name'][$idx] ?? ''),
            'error' => (int) ($files['error'][$idx] ?? UPLOAD_ERR_NO_FILE),
            'size' => (int) ($files['size'][$idx] ?? 0),
        ];
    }
} else {
    $normalized[] = [
        'name' => (string) $files['name'],
        'tmp_name' => (string) $files['tmp_name'],
        'error' => (int) $files['error'],
        'size' => (int) $files['size'],
    ];
}

$manifest = read_uploaded_manifest($manifestPath);
$saved = [];

foreach ($normalized as $file) {
    if ($file['error'] !== UPLOAD_ERR_OK || $file['size'] <= 0) {
        continue;
    }
    if (!preg_match('/\.csv$/i', $file['name'])) {
        continue;
    }
    $slug = slugify($file['name']);
    $filename = $slug . '-' . date('Ymd-His') . '.csv';
    $target = $uploadDir . DIRECTORY_SEPARATOR . $filename;
    if (!move_uploaded_file($file['tmp_name'], $target)) {
        continue;
    }

    $summary = summarize_csv($target);
    $entry = [
        'id' => $slug . '-' . substr(sha1($filename), 0, 8),
        'displayName' => preg_replace('/\.csv$/i', '', $file['name']),
        'file' => 'uploads/' . $filename,
        'source' => 'server',
        'score' => $summary['score'],
        'controls' => $summary['controls'],
        'complete' => $summary['complete'],
        'partial' => $summary['partial'],
        'failed' => $summary['failed'],
        'note' => 'Uploaded through local XAMPP CSV storage.',
    ];
    $manifest[] = $entry;
    $saved[] = $entry;
}

file_put_contents($manifestPath, json_encode(['tenants' => $manifest], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

echo json_encode([
    'ok' => true,
    'saved' => $saved,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

