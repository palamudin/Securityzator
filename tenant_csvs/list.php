<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

$baseDir = __DIR__;
$seedManifest = $baseDir . DIRECTORY_SEPARATOR . 'manifest.json';
$uploadManifest = $baseDir . DIRECTORY_SEPARATOR . 'uploaded_manifest.json';

function read_manifest(string $path): array {
    if (!is_file($path)) {
        return [];
    }
    $json = json_decode((string) file_get_contents($path), true);
    return is_array($json) && isset($json['tenants']) && is_array($json['tenants'])
        ? $json['tenants']
        : [];
}

$tenants = [];

foreach (read_manifest($seedManifest) as $tenant) {
    if (!isset($tenant['id'], $tenant['file'])) {
        continue;
    }
    $tenant['source'] = $tenant['source'] ?? 'seed';
    $tenant['url'] = 'tenant_csvs/' . ltrim((string) $tenant['file'], '/\\');
    $tenants[] = $tenant;
}

foreach (read_manifest($uploadManifest) as $tenant) {
    if (!isset($tenant['id'], $tenant['file'])) {
        continue;
    }
    $tenant['source'] = $tenant['source'] ?? 'server';
    $tenant['url'] = 'tenant_csvs/' . ltrim((string) $tenant['file'], '/\\');
    $tenants[] = $tenant;
}

echo json_encode([
    'generatedFrom' => 'tenant_csvs',
    'tenants' => $tenants,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

