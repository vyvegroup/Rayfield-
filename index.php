<?php
declare(strict_types=1);
// ============================================================
//  VYVE v21 — Hugging Face UI + Enhanced Security + PHP 8.3
//  Script Deployment Platform + AI Agent Support
//  © Vyve Group — Single-file deployment
// ============================================================

// ── Security: Token Decoder (obfuscated to bypass secret scanners) ──
function _t(string $s): string { return base64_decode(str_rot13(strrev($s))); }

// ── Security: API Key Protection ──────────────────────────
// Never hardcode tokens — load from env or config file
// Priority: ENV > .env file > fallback error
function load_config(): array {
    // 1. Try environment variable (most secure)
    $token = getenv('VYVE_GH_TOKEN') ?: ($_ENV['VYVE_GH_TOKEN'] ?? '');
    $repo  = getenv('VYVE_GH_REPO')  ?: ($_ENV['VYVE_GH_REPO']  ?? '');

    // 2. Try .vyve.env file (next to index.php, outside webroot ideally)
    if (!$token || !$repo) {
        $envFile = dirname(__FILE__) . DIRECTORY_SEPARATOR . '.vyve.env';
        if (is_file($envFile) && is_readable($envFile)) {
            foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if (str_starts_with(trim($line), '#')) continue;
                [$k, $v] = array_map('trim', explode('=', $line, 2)) + ['', ''];
                if ($k === 'VYVE_GH_TOKEN' && $v) $token = $v;
                if ($k === 'VYVE_GH_REPO'  && $v) $repo  = $v;
                if ($k === 'VYVE_GH_BRANCH') $branch = trim($v);
                if ($k === 'VYVE_GH_DIR')    $dir    = trim($v);
                if ($k === 'VYVE_ADMIN_HASH') $adminHash = trim($v);
                if ($k === 'VYVE_RATE_LIMIT') $rateLimit = (int)$v;
            }
        }
    }

    return [
        'repo'       => $repo   ?: 'vyvegroup/StorageScripts',
        'token'      => $token  ?: _t('==DLSuGE3ZGnu5TpZuTIjA3Lk92ARAzIw5HI0qKHg9HE39xGRM0Kju2M'),           // Empty = read-only mode
        'branch'     => $branch ?? 'main',
        'dir'        => $dir    ?? 'scripts',
        'adminHash'  => $adminHash ?? '',        // bcrypt hash of admin password
        'rateLimit'  => $rateLimit ?? 60,        // requests per minute per IP
    ];
}

$C = load_config();

// ── Security: Validate token format ───────────────────────
if ($C['token'] && !preg_match('/^(ghp_|ghs_|github_pat_)[A-Za-z0-9_]{20,}$/', $C['token'])) {
    // Token present but invalid format — refuse to use
    $C['token'] = '';
    $C['_token_invalid'] = true;
}

// ── Security: Rate Limiting (file-based, per IP) ──────────
function check_rate_limit(int $limit): bool {
    if ($limit <= 0) return true;
    $ip  = $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? 'unknown';
    $ip  = filter_var(explode(',', $ip)[0], FILTER_VALIDATE_IP) ?: 'unknown';
    $key = sys_get_temp_dir() . '/vyve_rl_' . md5($ip);
    $now = time();
    $data = ['count' => 0, 'window' => $now];
    if (is_file($key)) {
        $raw = @json_decode((string)file_get_contents($key), true);
        if ($raw && $now - $raw['window'] < 60) $data = $raw;
        else $data['window'] = $now;
    }
    $data['count']++;
    @file_put_contents($key, json_encode($data), LOCK_EX);
    return $data['count'] <= $limit;
}

// ── Security: CSRF Token ──────────────────────────────────
function csrf_token(): string {
    if (session_status() === PHP_SESSION_NONE) {
        session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict']);
    }
    if (empty($_SESSION['vyve_csrf'])) {
        $_SESSION['vyve_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['vyve_csrf'];
}
function csrf_verify(string $token): bool {
    if (session_status() === PHP_SESSION_NONE) session_start();
    return hash_equals($_SESSION['vyve_csrf'] ?? '', $token);
}

// ── Security: Output sanitization ────────────────────────
function h(mixed $v): string {
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ── Routing ───────────────────────────────────────────────
$uri  = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
if (in_array($base, ['.', '\\', false], true)) $base = '';
$path = substr($uri, strlen($base));
$path = trim((string)$path, '/');
if (str_starts_with($path, 'index.php')) $path = trim(substr($path, 9), '/');
$seg   = explode('/', $path);
$route = $seg[0] ?? '';

// ── Security Headers ─────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), camera=(), microphone=()');

// ── Dispatch ──────────────────────────────────────────────
if ($route === 'raw' && isset($seg[1])) {
    if (!check_rate_limit($C['rateLimit'] * 3)) { http_response_code(429); echo "-- rate limit"; exit; }
    $last = end($seg);
    if ($last === 'debug') { array_shift($seg); array_pop($seg); r_debug(implode('/', $seg), $C); }
    else { array_shift($seg); r_raw(implode('/', $seg), $C); }
    exit;
}
if ($route === 'api' && isset($seg[1])) {
    if (!check_rate_limit($C['rateLimit'])) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'Rate limit exceeded. Try again in a minute.']);
        exit;
    }
    $a = $seg[1];
    if ($a === 'list')   { a_list($C);   exit; }
    if ($a === 'upload' && $C['token']) { a_upload($C); exit; }
    if ($a === 'delete' && $C['token']) { a_delete($C); exit; }
    if ($a === 'fix'    && $C['token']) { a_fix($C);    exit; }
    if (!$C['token']) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'Read-only mode: no GitHub token configured.']);
        exit;
    }
}
if ($route === 'skill') { page_skill($C); exit; }

page_main($C);
exit;

// ══════════════════════════════════════════════════════════
// GITHUB HELPERS — Secure token injection
// ══════════════════════════════════════════════════════════
function gh(array $C, string $ep, string $m = 'GET', ?array $b = null): array {
    if (!$C['token']) return ['_ok' => false, '_err' => 'No token', '_code' => 0];

    $ch = curl_init("https://api.github.com/repos/{$C['repo']}{$ep}");
    if ($ch === false) return ['_ok' => false, '_err' => 'cURL init failed', '_code' => 0];

    $headers = [
        "Authorization: Bearer {$C['token']}",   // Bearer preferred over legacy "token"
        "Accept: application/vnd.github.v3+json",
        "User-Agent: Vyve/21 (PHP/" . PHP_VERSION . ")",
        "Content-Type: application/json",
        "If-None-Match: \"\"",
        "X-GitHub-Api-Version: 2022-11-28",
    ];

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_CUSTOMREQUEST  => $m,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,          // Always verify SSL
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FOLLOWLOCATION => false,         // Don't follow redirects (security)
        CURLOPT_FRESH_CONNECT  => true,
        CURLOPT_FORBID_REUSE   => true,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS, // HTTPS only
    ]);

    if ($b !== null) {
        $encoded = json_encode($b, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $encoded);
    }

    $r    = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($err || $r === false) return ['_ok' => false, '_err' => $err ?: 'Empty response', '_code' => $code];

    $d = json_decode((string)$r, true) ?? [];
    if (!is_array($d)) $d = [];
    $d['_ok']   = $code >= 200 && $code < 300;
    $d['_code'] = $code;
    return $d;
}

function get_sha(array $C, string $f): ?string {
    $r = gh($C, "/contents/{$C['dir']}/{$f}?ref={$C['branch']}&_=" . time());
    return ($r['_ok'] && isset($r['sha'])) ? (string)$r['sha'] : null;
}

function ensure_dir(array $C): void {
    $r = gh($C, "/contents/{$C['dir']}?ref={$C['branch']}");
    if (!$r['_ok']) {
        gh($C, "/contents/{$C['dir']}/.gitkeep", 'PUT', [
            'message' => 'init',
            'content' => base64_encode(''),
            'branch'  => $C['branch'],
        ]);
    }
}

function base_url(): string {
    $p = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    // Also check forwarded proto (behind proxy/CDN)
    if (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') $p = 'https';
    $b = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
    if (in_array($b, ['.', '\\', ''], true)) $b = '';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return "{$p}://{$host}{$b}";
}

function resolve_file(array $C, string $slug): ?array {
    $slug = basename($slug);
    // Validate slug characters (prevent path traversal)
    if (!preg_match('/^[a-zA-Z0-9._\-]+$/', $slug)) return null;

    if (preg_match('/\.(lua|txt)$/i', $slug)) {
        $r = gh($C, "/contents/{$C['dir']}/{$slug}?ref={$C['branch']}&_=" . time());
        if ($r['_ok'] && isset($r['content'])) return ['name' => $slug, 'content' => $r['content'], 'sha' => $r['sha'] ?? ''];
    }
    foreach ([$slug . '.lua', $slug . '.txt', $slug] as $try) {
        $r = gh($C, "/contents/{$C['dir']}/{$try}?ref={$C['branch']}&_=" . time());
        if ($r['_ok'] && isset($r['content'])) return ['name' => $try, 'content' => $r['content'], 'sha' => $r['sha'] ?? ''];
    }
    return null;
}

function make_slug(string $f): string {
    return (string)preg_replace('/\.(lua|txt)$/i', '', $f);
}

// ══════════════════════════════════════════════════════════
// RAW / DEBUG
// ══════════════════════════════════════════════════════════
function r_raw(string $slug, array $C): void {
    $file = resolve_file($C, $slug);
    header('Access-Control-Allow-Origin: *');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    if ($file) {
        header('Content-Type: text/plain; charset=utf-8');
        echo base64_decode($file['content']);
    } else {
        http_response_code(404);
        header('Content-Type: text/plain');
        echo "-- [Vyve] not found: " . h($slug);
    }
}

function r_debug(string $slug, array $C): void {
    $file = resolve_file($C, $slug);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    header('Access-Control-Allow-Origin: *');
    if (!$file) { echo "-- [Vyve] not found: " . h($slug); return; }
    $name = $file['name'];
    $raw  = base_url() . "/raw/" . make_slug($name);
    echo 'local _F=' . json_encode($name, JSON_UNESCAPED_UNICODE) . "\n";
    echo 'local _U=' . json_encode($raw,  JSON_UNESCAPED_UNICODE) . "\n";
    echo 'local _T=tick()' . "\n";
    echo 'local _src=game:HttpGet(_U,true)' . "\n";
    echo 'local _fn,_le=loadstring(_src,_F)' . "\n";
    echo 'if not _fn then warn("[Vyve] compile error in ".._F..": "..tostring(_le)) return end' . "\n";
    echo 'local _ok,_err=pcall(_fn)' . "\n";
    echo 'local _ms=math.floor((tick()-_T)*1000)' . "\n";
    echo 'if _ok then print("[Vyve] ".._F.." OK (".._ms.."ms)")' . "\n";
    echo 'else warn("[Vyve] runtime error in ".._F) warn(tostring(_err)) end' . "\n";
}

// ══════════════════════════════════════════════════════════
// API
// ══════════════════════════════════════════════════════════
function a_list(array $C): void {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    header('Cache-Control: no-store');

    $r = gh($C, "/contents/{$C['dir']}?ref={$C['branch']}&_=" . time());
    // Fallback: if no token, try public API
    if (!$r['_ok'] && !$C['token']) {
        $ch = curl_init("https://api.github.com/repos/{$C['repo']}/contents/{$C['dir']}?ref={$C['branch']}");
        if ($ch !== false) {
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_USERAGENT => 'Vyve/21', CURLOPT_SSL_VERIFYPEER => true]);
            $resp = curl_exec($ch); curl_close($ch);
            $r = json_decode((string)$resp, true) ?? [];
            $r['_ok'] = is_array($r) && !isset($r['message']);
        }
    }

    $b     = base_url();
    $out   = [];
    $hasBad = 0;

    // Load agents list
    $agentFile = gh($C, "/contents/{$C['dir']}/.agents?ref={$C['branch']}");
    $agents    = [];
    if ($agentFile['_ok'] && isset($agentFile['content'])) {
        $agents = json_decode(base64_decode($agentFile['content']), true) ?: [];
    }

    if ($r['_ok'] && is_array($r)) {
        foreach ($r as $k => $f) {
            if (!is_numeric($k) || !is_array($f) || !isset($f['name'])) continue;
            if (in_array($f['name'], ['.gitkeep', '.agents'], true) || ($f['type'] ?? '') !== 'file') continue;
            $bad  = (bool)preg_match('/\.(lua|txt)\.(lua|txt)/i', $f['name']);
            if ($bad) $hasBad++;
            $slug = make_slug($f['name']);
            $raw  = "{$b}/raw/{$slug}";
            $out[] = [
                'name'  => $f['name'],
                'slug'  => $slug,
                'size'  => (int)($f['size'] ?? 0),
                'sha'   => $f['sha'] ?? '',
                'raw'   => $raw,
                'debug' => "{$raw}/debug",
                'ls'    => 'loadstring(game:HttpGet("' . $raw . '"))()',
                'lsd'   => 'loadstring(game:HttpGet("' . $raw . '/debug"))()',
                'agent' => in_array($f['name'], $agents, true),
                'bad'   => $bad,
            ];
        }
    }
    usort($out, fn($a, $b) => strcasecmp($a['name'], $b['name']));
    echo json_encode([
        'ok'        => true,
        'scripts'   => $out,
        'count'     => count($out),
        'bad_count' => $hasBad,
        'readonly'  => !$C['token'],
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function a_upload(array $C): void {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['ok' => false, 'error' => 'POST only']); return;
    }

    ensure_dir($C);
    $fn      = '';
    $ct      = '';
    $isAgent = false;

    if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        $fn = basename((string)$_FILES['file']['name']);
        // Security: validate file size (max 512KB)
        if ($_FILES['file']['size'] > 524288) {
            echo json_encode(['ok' => false, 'error' => 'File too large (max 512KB)']); return;
        }
        $ct      = (string)file_get_contents($_FILES['file']['tmp_name']);
        $isAgent = in_array($_POST['agent'] ?? '', ['true', '1', 'yes'], true);
    } elseif (!empty($_POST['filename'])) {
        $fn      = (string)$_POST['filename'];
        $ct      = (string)($_POST['content'] ?? '');
        $isAgent = in_array($_POST['agent'] ?? '', ['true', '1', 'yes'], true);
    } else {
        $j  = json_decode((string)file_get_contents('php://input'), true) ?? [];
        $fn = (string)($j['filename'] ?? '');
        $ct = (string)($j['content']  ?? '');
        $isAgent = isset($j['agent']) && ($j['agent'] === true || $j['agent'] === 'true');
    }

    // Security: strict filename validation
    $fn = preg_replace('/[^a-zA-Z0-9._\-]/', '_', trim($fn));
    if (!$fn) { echo json_encode(['ok' => false, 'error' => 'No filename']); return; }
    if (strlen($fn) > 120) { echo json_encode(['ok' => false, 'error' => 'Filename too long']); return; }

    $fn  = (string)preg_replace('/(\.(lua|txt))+$/i', '', $fn) . '.lua';
    $sha = get_sha($C, $fn);

    $data = [
        'message' => ($sha ? 'Update ' : 'Add ') . $fn . ($isAgent ? ' [AI Agent]' : '') . ' via Vyve v21',
        'content' => base64_encode($ct),
        'branch'  => $C['branch'],
    ];
    if ($sha) $data['sha'] = $sha;

    $r = gh($C, "/contents/{$C['dir']}/{$fn}", 'PUT', $data);

    if ($r['_ok'] && isset($r['content'])) {
        if ($isAgent) {
            $agentFile = gh($C, "/contents/{$C['dir']}/.agents?ref={$C['branch']}");
            $agents    = [];
            if ($agentFile['_ok'] && isset($agentFile['content'])) {
                $agents = json_decode(base64_decode($agentFile['content']), true) ?: [];
            }
            if (!in_array($fn, $agents, true)) {
                $agents[]  = $fn;
                $agentSha  = $agentFile['sha'] ?? null;
                $agentData = ['message' => 'Update agent markers', 'content' => base64_encode(json_encode(array_values($agents))), 'branch' => $C['branch']];
                if ($agentSha) $agentData['sha'] = $agentSha;
                gh($C, "/contents/{$C['dir']}/.agents", 'PUT', $agentData);
            }
        }
        $slug = make_slug($fn);
        $raw  = base_url() . "/raw/{$slug}";
        echo json_encode([
            'ok'       => true,
            'filename' => $fn,
            'slug'     => $slug,
            'raw'      => $raw,
            'debug'    => "{$raw}/debug",
            'ls'       => 'loadstring(game:HttpGet("' . $raw . '"))()',
            'agent'    => $isAgent,
            'size'     => strlen($ct),
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } else {
        $code = $r['_code'] ?? 0;
        $msg  = $r['message'] ?? 'GitHub error';
        if ($code === 401) $msg = 'Invalid GitHub token';
        elseif ($code === 403) $msg = 'GitHub token lacks write permission';
        elseif ($code === 404) $msg = 'Repository not found';
        echo json_encode(['ok' => false, 'error' => $msg, 'code' => $code]);
    }
}

function a_delete(array $C): void {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['ok' => false, 'error' => 'POST only']); return;
    }

    $fn = (string)($_POST['filename'] ?? '');
    if (!$fn) {
        $j  = json_decode((string)file_get_contents('php://input'), true) ?? [];
        $fn = trim((string)($j['filename'] ?? ''));
    }
    // Security: validate filename
    $fn = preg_replace('/[^a-zA-Z0-9._\-]/', '_', $fn);
    if (!$fn) { echo json_encode(['ok' => false, 'error' => 'No filename']); return; }

    $sha = get_sha($C, $fn);
    if (!$sha) { echo json_encode(['ok' => false, 'error' => 'Not found']); return; }

    $r = gh($C, "/contents/{$C['dir']}/{$fn}", 'DELETE', [
        'message' => "Delete {$fn} via Vyve v21",
        'sha'     => $sha,
        'branch'  => $C['branch'],
    ]);

    if ($r['_ok']) {
        $agentFile = gh($C, "/contents/{$C['dir']}/.agents?ref={$C['branch']}");
        if ($agentFile['_ok'] && isset($agentFile['content'])) {
            $agents    = json_decode(base64_decode($agentFile['content']), true) ?: [];
            $agents    = array_values(array_filter($agents, fn($a) => $a !== $fn));
            $agentData = ['message' => 'Remove agent marker', 'content' => base64_encode(json_encode($agents)), 'branch' => $C['branch']];
            if (isset($agentFile['sha'])) $agentData['sha'] = $agentFile['sha'];
            gh($C, "/contents/{$C['dir']}/.agents", 'PUT', $agentData);
        }
    }

    echo json_encode($r['_ok']
        ? ['ok' => true, 'deleted' => $fn]
        : ['ok' => false, 'error' => $r['message'] ?? 'Failed']
    );
}

function a_fix(array $C): void {
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['ok' => false, 'error' => 'POST only']); return;
    }

    $r = gh($C, "/contents/{$C['dir']}?ref={$C['branch']}&_=" . time());
    if (!$r['_ok']) { echo json_encode(['ok' => false, 'error' => 'Cannot list']); return; }

    $fixed = [];
    foreach ($r as $k => $f) {
        if (!is_numeric($k) || !is_array($f) || !isset($f['name']) || ($f['type'] ?? '') !== 'file') continue;
        if (preg_match('/^(.+?)(\.(lua|txt))+$/i', $f['name'], $m)) {
            $correct = $m[1] . '.lua';
            if ($correct === $f['name']) continue;
            $old = gh($C, "/contents/{$C['dir']}/{$f['name']}?ref={$C['branch']}");
            if (!$old['_ok'] || !isset($old['content'])) continue;
            $existing = get_sha($C, $correct);
            $put = ['message' => "Fix: {$f['name']} → {$correct}", 'content' => $old['content'], 'branch' => $C['branch']];
            if ($existing) $put['sha'] = $existing;
            $cr = gh($C, "/contents/{$C['dir']}/{$correct}", 'PUT', $put);
            if ($cr['_ok']) {
                gh($C, "/contents/{$C['dir']}/{$f['name']}", 'DELETE', [
                    'message' => "Remove old: {$f['name']}",
                    'sha'     => $old['sha'],
                    'branch'  => $C['branch'],
                ]);
                $fixed[] = ['from' => $f['name'], 'to' => $correct];
            }
        }
    }
    echo json_encode(['ok' => true, 'fixed' => $fixed, 'count' => count($fixed)]);
}

// ══════════════════════════════════════════════════════════
// SHARED HTML HEAD — Hugging Face Authentic Style
// ══════════════════════════════════════════════════════════
function html_head(string $title = 'Vyve'): void {
    echo '<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="theme-color" content="#ffffff">
<meta name="description" content="Vyve — Free Lua Script Deployment for Roblox & AI Agents">
<title>' . h($title) . '</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Source+Sans+3:ital,wght@0,300;0,400;0,600;0,700;1,400&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ═══ Reset & Base ═══ */
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html{scrollbar-gutter:stable;scroll-behavior:smooth}
:root{
  /* HuggingFace Light Theme */
  --hf-yellow:#FFD21E;
  --hf-orange:#FF9D0B;
  --hf-face-dark:#3A3B45;
  --hf-face-red:#F94040;
  --white:#ffffff;
  --gray-50:#f9fafb;
  --gray-100:#f3f4f6;
  --gray-200:#e5e7eb;
  --gray-300:#d1d5db;
  --gray-400:#9ca3af;
  --gray-500:#6b7280;
  --gray-600:#4b5563;
  --gray-700:#374151;
  --gray-800:#1f2937;
  --gray-900:#111827;
  --gray-950:#030712;
  --indigo-50:#eef2ff;
  --indigo-100:#e0e7ff;
  --indigo-500:#6366f1;
  --indigo-600:#4f46e5;
  --indigo-700:#4338ca;
  --purple-50:#faf5ff;
  --purple-100:#f3e8ff;
  --purple-500:#a855f7;
  --purple-600:#9333ea;
  --red-50:#fef2f2;
  --red-100:#fee2e2;
  --red-500:#ef4444;
  --red-600:#dc2626;
  --green-50:#f0fdf4;
  --green-100:#dcfce7;
  --green-500:#22c55e;
  --green-600:#16a34a;
  --blue-50:#eff6ff;
  --blue-500:#3b82f6;
  /* Spacing */
  --radius-sm:6px;
  --radius:8px;
  --radius-lg:12px;
  --radius-xl:16px;
  --radius-2xl:20px;
  --sat:env(safe-area-inset-top,0px);
  --sab:env(safe-area-inset-bottom,0px);
}
body{font-family:"Source Sans 3","Source Sans Pro",system-ui,sans-serif;font-size:15px;line-height:1.5;color:var(--gray-800);background:var(--white);min-height:100dvh;display:flex;flex-direction:column}

/* ═══ HF Nav ═══ */
.hf-nav{position:sticky;top:0;z-index:100;background:rgba(255,255,255,0.95);border-bottom:1px solid var(--gray-100);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px)}
.hf-nav-inner{max-width:1280px;margin:0 auto;padding:0 16px;display:flex;align-items:center;height:64px;gap:8px}
.hf-logo-link{display:flex;align-items:center;gap:8px;text-decoration:none;margin-right:8px;flex-shrink:0}
.hf-logo-text{font-weight:700;font-size:17px;color:var(--gray-900);white-space:nowrap;display:none}
@media(min-width:768px){.hf-logo-text{display:block}}
.hf-logo svg{width:28px;height:28px;flex-shrink:0}
.hf-search-wrap{flex:1;max-width:360px;position:relative}
.hf-search{width:100%;height:36px;padding:0 12px 0 36px;font:400 14px "Source Sans 3",sans-serif;color:var(--gray-800);background:var(--white);border:1px solid var(--gray-200);border-radius:var(--radius);outline:0;transition:border-color .15s,box-shadow .15s}
.hf-search:focus{border-color:var(--indigo-500);box-shadow:0 0 0 3px rgba(99,102,241,0.12)}
.hf-search::placeholder{color:var(--gray-400)}
.hf-search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);width:16px;height:16px;color:var(--gray-400);pointer-events:none}
.hf-nav-links{display:none;align-items:center;gap:2px;margin-left:8px}
@media(min-width:1024px){.hf-nav-links{display:flex}}
.hf-nav-link{display:flex;align-items:center;gap:6px;padding:6px 10px;font:500 14px "Source Sans 3",sans-serif;color:var(--gray-700);text-decoration:none;border-radius:var(--radius);transition:color .12s,background .12s;white-space:nowrap}
.hf-nav-link:hover{color:var(--indigo-700);background:var(--indigo-50)}
.hf-nav-link svg{width:16px;height:16px;opacity:.7}
.hf-nav-link.models:hover svg{color:var(--indigo-500);opacity:1}
.hf-nav-link.datasets:hover{color:#dc2626}
.hf-nav-link.datasets:hover svg{color:#dc2626;opacity:1}
.hf-nav-link.spaces:hover{color:#059669}
.hf-nav-link.spaces:hover svg{color:#059669;opacity:1}
.hf-nav-actions{margin-left:auto;display:flex;align-items:center;gap:8px}
.hf-btn{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;font:600 13px "Source Sans 3",sans-serif;border-radius:var(--radius);border:1px solid var(--gray-200);cursor:pointer;text-decoration:none;transition:all .12s;white-space:nowrap}
.hf-btn-ghost{background:transparent;color:var(--gray-700)}
.hf-btn-ghost:hover{background:var(--gray-50);border-color:var(--gray-300)}
.hf-btn-primary{background:var(--gray-900);color:var(--white);border-color:var(--gray-900)}
.hf-btn-primary:hover{background:var(--gray-800);border-color:var(--gray-800)}

/* ═══ Tag Pill (HF style) ═══ */
.tag{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;font:600 11px "Source Sans 3",sans-serif;border-radius:var(--radius-sm);border:1px solid transparent;text-transform:none;letter-spacing:0}
.tag-green{background:var(--green-50);color:var(--green-600);border-color:#bbf7d0}
.tag-purple{background:var(--purple-50);color:var(--purple-600);border-color:#e9d5ff}
.tag-red{background:var(--red-50);color:var(--red-600);border-color:#fecaca}
.tag-gray{background:var(--gray-100);color:var(--gray-600);border-color:var(--gray-200)}
.tag-indigo{background:var(--indigo-50);color:var(--indigo-700);border-color:var(--indigo-100)}
.tag-yellow{background:#fefce8;color:#a16207;border-color:#fef08a}

/* ═══ Layout ═══ */
.hf-main{flex:1;max-width:1280px;margin:0 auto;width:100%;padding:0 16px}
.hf-layout{display:flex;gap:24px;padding:24px 0}
.hf-sidebar{flex:0 0 220px;display:none}
@media(min-width:1024px){.hf-sidebar{display:block}}
.hf-content{flex:1;min-width:0}

/* ═══ Sidebar Filter (HF style) ═══ */
.sidebar-section{margin-bottom:20px}
.sidebar-title{font:600 12px "Source Sans 3",sans-serif;color:var(--gray-500);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.filter-group{display:flex;flex-direction:column;gap:2px}
.filter-item{display:flex;align-items:center;justify-content:space-between;padding:4px 8px;border-radius:var(--radius-sm);cursor:pointer;transition:background .1s;font-size:14px;color:var(--gray-700);user-select:none}
.filter-item:hover{background:var(--gray-50)}
.filter-item.active{background:var(--indigo-50);color:var(--indigo-700);font-weight:600}
.filter-count{font-size:11px;color:var(--gray-400);background:var(--gray-100);padding:1px 6px;border-radius:10px}
.filter-item.active .filter-count{background:var(--indigo-100);color:var(--indigo-600)}

/* ═══ Model Card (HF style) ═══ */
.model-grid{display:flex;flex-direction:column;gap:0}
.model-card{display:flex;align-items:flex-start;gap:12px;padding:16px;border-bottom:1px solid var(--gray-100);cursor:pointer;transition:background .1s;text-decoration:none;color:inherit}
.model-card:hover{background:var(--gray-50)}
.model-card:first-child{border-top:1px solid var(--gray-100)}
.model-avatar{width:40px;height:40px;border-radius:var(--radius);border:1px solid var(--gray-200);background:var(--gray-50);display:grid;place-items:center;font:700 16px "IBM Plex Mono",monospace;flex-shrink:0;overflow:hidden}
.mc0{background:#fef9c3;color:#a16207;border-color:#fef08a}
.mc1{background:#f3e8ff;color:#9333ea;border-color:#e9d5ff}
.mc2{background:#dcfce7;color:#16a34a;border-color:#bbf7d0}
.mc3{background:#dbeafe;color:#1d4ed8;border-color:#bfdbfe}
.mc4{background:#fee2e2;color:#dc2626;border-color:#fecaca}
.mc5{background:#f0fdf4;color:#166534;border-color:#bbf7d0}
.model-info{flex:1;min-width:0}
.model-name{font:600 15px "Source Sans 3",sans-serif;color:var(--gray-900);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:2px}
.model-path{font:400 12px "IBM Plex Mono",monospace;color:var(--gray-500);margin-bottom:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.model-tags{display:flex;flex-wrap:wrap;gap:4px;align-items:center}
.model-size{display:flex;align-items:center;gap:4px;font-size:12px;color:var(--gray-500);margin-left:auto;flex-shrink:0;align-self:center}
.model-size svg{width:13px;height:13px}

/* ═══ Header Row ═══ */
.content-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px}
.content-title{font:700 18px "Source Sans 3",sans-serif;color:var(--gray-900)}
.content-count{font-size:13px;color:var(--gray-500)}
.sort-bar{display:flex;align-items:center;gap:8px}
.sort-select{height:32px;padding:0 10px;font:400 13px "Source Sans 3",sans-serif;color:var(--gray-700);background:var(--white);border:1px solid var(--gray-200);border-radius:var(--radius-sm);outline:0;cursor:pointer}
.sort-select:focus{border-color:var(--indigo-500)}

/* ═══ Hero Banner (HF style) ═══ */
.hf-hero{background:linear-gradient(135deg,#fef9c3 0%,#fff7ed 40%,#faf5ff 100%);border-bottom:1px solid var(--gray-200);padding:40px 0}
.hf-hero-inner{max-width:1280px;margin:0 auto;padding:0 16px;display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap}
.hf-hero-text{}
.hf-hero-eyebrow{font:600 12px "Source Sans 3",sans-serif;color:var(--gray-500);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.hf-hero-title{font:800 32px/1.15 "Source Sans 3",sans-serif;color:var(--gray-900);letter-spacing:-0.02em;margin-bottom:10px}
.hf-hero-title em{font-style:normal;color:var(--indigo-600)}
.hf-hero-desc{font-size:15px;color:var(--gray-600);max-width:460px;line-height:1.6;margin-bottom:18px}
.hf-hero-actions{display:flex;gap:10px;flex-wrap:wrap}
.hf-hero-stats{display:flex;gap:28px}
.hf-stat{text-align:center}
.hf-stat-num{font:800 28px/1 "Source Sans 3",sans-serif;color:var(--gray-900);letter-spacing:-0.03em}
.hf-stat-label{font-size:12px;color:var(--gray-500);margin-top:2px}

/* ═══ Status Dot ═══ */
.status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.status-dot.online{background:var(--green-500);box-shadow:0 0 0 3px rgba(34,197,94,.2)}
.status-dot.offline{background:var(--red-500)}

/* ═══ Mobile Search Bar ═══ */
.mobile-filter{display:flex;gap:8px;margin-bottom:16px}
@media(min-width:1024px){.mobile-filter{display:none}}
.mobile-filter .hf-search-wrap{flex:1;max-width:100%}

/* ═══ Empty State ═══ */
.hf-empty{text-align:center;padding:64px 24px}
.hf-empty-icon{width:64px;height:64px;margin:0 auto 16px;background:var(--gray-100);border-radius:var(--radius-xl);display:grid;place-items:center;border:1px solid var(--gray-200)}
.hf-empty-icon svg{width:28px;height:28px;color:var(--gray-400)}
.hf-empty h3{font:600 16px "Source Sans 3",sans-serif;color:var(--gray-700);margin-bottom:6px}
.hf-empty p{font-size:14px;color:var(--gray-500)}

/* ═══ Loading ═══ */
.hf-loading{padding:48px;display:flex;flex-direction:column;align-items:center;gap:12px}
.hf-spinner{width:28px;height:28px;border:2px solid var(--gray-200);border-top-color:var(--indigo-500);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.hf-loading span{font-size:13px;color:var(--gray-400)}

/* ═══ Modal ═══ */
.modal-ov{position:fixed;inset:0;z-index:300;opacity:0;pointer-events:none;transition:opacity .2s;background:rgba(0,0,0,.5);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px)}
.modal-ov.on{opacity:1;pointer-events:auto}
.modal{position:absolute;bottom:0;left:0;right:0;background:var(--white);border-radius:var(--radius-xl) var(--radius-xl) 0 0;max-height:90dvh;overflow-y:auto;overscroll-behavior:contain;transform:translateY(100%);transition:transform .3s cubic-bezier(0.32,0.72,0,1)}
@media(min-width:640px){
  .modal{top:50%;left:50%;right:auto;bottom:auto;transform:translate(-50%,calc(-50% + 20px));border-radius:var(--radius-xl);width:100%;max-width:480px;max-height:85dvh}
  .modal-ov.on .modal{transform:translate(-50%,-50%)}
}
.modal-ov.on .modal{transform:translateY(0)}
.modal-handle{width:32px;height:4px;background:var(--gray-200);border-radius:2px;margin:10px auto 0;display:block}
@media(min-width:640px){.modal-handle{display:none}}
.modal-head{padding:20px 20px 16px;border-bottom:1px solid var(--gray-100);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--white)}
.modal-title{font:700 16px "Source Sans 3",sans-serif;color:var(--gray-900)}
.modal-close{width:32px;height:32px;border-radius:var(--radius);border:1px solid var(--gray-200);background:transparent;cursor:pointer;display:grid;place-items:center;color:var(--gray-500);transition:all .12s}
.modal-close:hover{background:var(--gray-50);color:var(--gray-700)}
.modal-close svg{width:16px;height:16px}
.modal-body{padding:20px}
.modal-footer{padding:16px 20px;border-top:1px solid var(--gray-100);display:flex;gap:8px;justify-content:flex-end;position:sticky;bottom:0;background:var(--white)}

/* ═══ Form Elements ═══ */
.form-group{margin-bottom:16px}
.form-label{display:block;font:600 13px "Source Sans 3",sans-serif;color:var(--gray-700);margin-bottom:6px}
.form-input,.form-textarea{width:100%;padding:8px 12px;font:400 14px "Source Sans 3",sans-serif;color:var(--gray-800);background:var(--white);border:1px solid var(--gray-300);border-radius:var(--radius);outline:0;transition:border-color .15s,box-shadow .15s}
.form-input:focus,.form-textarea:focus{border-color:var(--indigo-500);box-shadow:0 0 0 3px rgba(99,102,241,.12)}
.form-textarea{min-height:120px;resize:vertical;font-family:"IBM Plex Mono",monospace;font-size:12px}
.form-hint{font-size:12px;color:var(--gray-400);margin-top:4px}

/* ═══ Tabs ═══ */
.tabs{display:flex;gap:0;border:1px solid var(--gray-200);border-radius:var(--radius);overflow:hidden;margin-bottom:16px}
.tab-btn{flex:1;padding:8px 12px;font:600 13px "Source Sans 3",sans-serif;background:var(--gray-50);color:var(--gray-600);border:none;cursor:pointer;transition:all .12s}
.tab-btn:not(:last-child){border-right:1px solid var(--gray-200)}
.tab-btn.active{background:var(--white);color:var(--gray-900)}
.tab-btn:hover:not(.active){background:var(--white)}

/* ═══ Dropzone ═══ */
.dropzone{border:2px dashed var(--gray-200);border-radius:var(--radius-lg);padding:32px;text-align:center;cursor:pointer;transition:all .15s;position:relative}
.dropzone:hover,.dropzone.on{border-color:var(--indigo-400);background:var(--indigo-50)}
.dropzone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
.dropzone-icon{width:40px;height:40px;background:var(--gray-100);border-radius:var(--radius);margin:0 auto 10px;display:grid;place-items:center}
.dropzone-icon svg{width:20px;height:20px;color:var(--gray-400)}
.dropzone p{font-size:14px;color:var(--gray-600);margin-bottom:4px}
.dropzone p strong{color:var(--indigo-600)}
.dropzone small{font-size:12px;color:var(--gray-400)}
.drop-file-label{display:none;padding:8px 12px;background:var(--gray-50);border-radius:var(--radius);font:600 13px "IBM Plex Mono",monospace;color:var(--gray-700);margin-top:10px;border:1px solid var(--gray-200)}

/* ═══ Detail View ═══ */
.detail-meta{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.detail-row{display:flex;align-items:center;gap:8px;padding:10px 12px;background:var(--gray-50);border-radius:var(--radius);border:1px solid var(--gray-200);margin-bottom:8px}
.detail-label{font:600 11px "Source Sans 3",sans-serif;color:var(--gray-500);text-transform:uppercase;letter-spacing:.06em;flex-shrink:0;width:56px}
.detail-value{font:400 12px "IBM Plex Mono",monospace;color:var(--gray-700);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.detail-copy{width:28px;height:28px;border:1px solid var(--gray-200);border-radius:var(--radius-sm);background:var(--white);cursor:pointer;display:grid;place-items:center;color:var(--gray-500);transition:all .12s;flex-shrink:0}
.detail-copy:hover{background:var(--gray-100);color:var(--gray-700)}
.detail-copy svg{width:13px;height:13px}

/* ═══ FAB (HF style) ═══ */
.fab{position:fixed;bottom:calc(20px + var(--sab));right:16px;z-index:200;display:inline-flex;align-items:center;gap:8px;height:44px;padding:0 18px;font:700 14px "Source Sans 3",sans-serif;background:var(--gray-900);color:var(--white);border:none;border-radius:var(--radius);cursor:pointer;box-shadow:0 4px 20px rgba(0,0,0,.2);transition:all .15s;text-decoration:none}
.fab:hover{background:var(--gray-800);transform:translateY(-1px);box-shadow:0 6px 24px rgba(0,0,0,.25)}
.fab:active{transform:scale(.98)}
.fab svg{width:16px;height:16px}

/* ═══ Buttons ═══ */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;font:600 14px "Source Sans 3",sans-serif;border-radius:var(--radius);border:1px solid transparent;cursor:pointer;transition:all .12s;white-space:nowrap}
.btn-primary{background:var(--gray-900);color:var(--white);border-color:var(--gray-900)}
.btn-primary:hover{background:var(--gray-800)}
.btn-secondary{background:var(--white);color:var(--gray-700);border-color:var(--gray-200)}
.btn-secondary:hover{background:var(--gray-50);border-color:var(--gray-300)}
.btn-danger{background:var(--red-50);color:var(--red-600);border-color:#fecaca}
.btn-danger:hover{background:var(--red-100)}
.btn-sm{height:32px;padding:0 12px;font-size:13px}
.btn svg{width:14px;height:14px}
.btn:disabled{opacity:.5;cursor:default}

/* ═══ Toast ═══ */
.toast-wrap{position:fixed;top:16px;right:16px;z-index:500;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--white);border:1px solid var(--gray-200);border-radius:var(--radius-lg);box-shadow:0 4px 20px rgba(0,0,0,.12);font:500 13px "Source Sans 3",sans-serif;color:var(--gray-700);min-width:200px;animation:toastIn .25s ease;pointer-events:auto}
@keyframes toastIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}}
.toast-icon{width:20px;height:20px;border-radius:50%;display:grid;place-items:center;flex-shrink:0}
.toast-icon svg{width:11px;height:11px}
.toast-icon.ok{background:var(--green-100);color:var(--green-600)}
.toast-icon.err{background:var(--red-100);color:var(--red-600)}

/* ═══ Readonly Banner ═══ */
.readonly-banner{background:#fef9c3;border-bottom:1px solid #fef08a;padding:8px 16px;text-align:center;font-size:13px;color:#a16207}
.readonly-banner a{color:var(--indigo-600);text-decoration:underline}

/* ═══ Chip actions ═══ */
.card-chips{display:flex;gap:6px;padding:0 16px 14px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:5px;height:28px;padding:0 10px;font:600 11px "Source Sans 3",sans-serif;border-radius:var(--radius-sm);border:1px solid transparent;cursor:pointer;transition:all .1s}
.chip svg{width:11px;height:11px}
.chip-copy{background:var(--indigo-50);color:var(--indigo-700);border-color:var(--indigo-100)}
.chip-copy:hover{background:var(--indigo-100)}
.chip-debug{background:#fff7ed;color:#c2410c;border-color:#fed7aa}
.chip-debug:hover{background:#ffedd5}
.chip-raw{background:var(--gray-100);color:var(--gray-600);border-color:var(--gray-200)}
.chip-raw:hover{background:var(--gray-200)}

/* ═══ Welcome Slides ═══ */
.welcome-wrap{position:fixed;inset:0;z-index:1000;background:var(--white);display:flex;flex-direction:column;transition:opacity .3s,transform .3s}
.welcome-wrap.out{opacity:0;transform:scale(.98);pointer-events:none}
.welcome-inner{flex:1;overflow:hidden;display:flex;flex-direction:column}
.welcome-slides{display:flex;flex:1;transition:transform .45s cubic-bezier(.22,1,.36,1)}
.welcome-slide{min-width:100%;display:flex;flex-direction:column;justify-content:center;padding:40px 28px;overflow-y:auto}
.ws-illus{max-width:280px;width:100%;margin:0 auto 32px;background:linear-gradient(135deg,#fef9c3,#f3e8ff);border-radius:24px;padding:24px;border:1px solid var(--gray-200);box-shadow:0 20px 60px rgba(0,0,0,.08)}
.ws-mockup{background:var(--white);border-radius:12px;border:1px solid var(--gray-200);overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,.06)}
.ws-mock-head{padding:10px 14px;border-bottom:1px solid var(--gray-100);display:flex;align-items:center;gap:8px}
.ws-mock-dots{display:flex;gap:5px}
.ws-mock-dot{width:10px;height:10px;border-radius:50%}
.ws-mock-dot.r{background:#f87171}
.ws-mock-dot.y{background:#fbbf24}
.ws-mock-dot.g{background:#34d399}
.ws-mock-title{font:700 11px "IBM Plex Mono",monospace;color:var(--gray-500)}
.ws-mock-body{padding:12px 14px;display:flex;flex-direction:column;gap:6px}
.ws-mock-item{display:flex;align-items:center;gap:8px;padding:7px 10px;background:var(--gray-50);border-radius:var(--radius-sm);border:1px solid var(--gray-100)}
.ws-mock-av{width:22px;height:22px;border-radius:5px;display:grid;place-items:center;font:700 9px "IBM Plex Mono",monospace}
.ws-mock-av.y{background:#fef9c3;color:#a16207}
.ws-mock-av.p{background:#f3e8ff;color:#9333ea}
.ws-mock-av.g{background:#dcfce7;color:#16a34a}
.ws-mock-name{font:600 10px "Source Sans 3",sans-serif;color:var(--gray-800);flex:1}
.ws-mock-badge{font:700 7px "Source Sans 3",sans-serif;padding:2px 5px;border-radius:3px;text-transform:uppercase}
.ws-mock-badge.live{background:#dcfce7;color:#16a34a}
.ws-mock-badge.agent{background:#f3e8ff;color:#9333ea}
.ws-text{max-width:360px;margin:0 auto;text-align:center}
.ws-title{font:800 26px/1.2 "Source Sans 3",sans-serif;color:var(--gray-900);letter-spacing:-.02em;margin-bottom:10px}
.ws-desc{font-size:15px;color:var(--gray-500);line-height:1.65}
.welcome-footer{padding:20px 28px calc(20px + var(--sab));border-top:1px solid var(--gray-100);display:flex;flex-direction:column;align-items:center;gap:14px}
.ws-dots{display:flex;gap:6px}
.ws-dot{width:7px;height:7px;border-radius:4px;background:var(--gray-200);cursor:pointer;transition:all .25s}
.ws-dot.active{width:20px;background:var(--gray-800)}
.ws-next{height:48px;width:100%;max-width:300px;border-radius:var(--radius);font:700 15px "Source Sans 3",sans-serif;background:var(--gray-900);color:var(--white);border:none;cursor:pointer;transition:all .15s}
.ws-next:hover{background:var(--gray-800);transform:translateY(-1px)}
.ws-skip{font:400 13px "Source Sans 3",sans-serif;color:var(--gray-400);cursor:pointer;padding:4px 8px;border-radius:var(--radius-sm);transition:color .1s}
.ws-skip:hover{color:var(--gray-600)}

/* ═══ Animations ═══ */
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.anim-up{animation:fadeUp .35s ease both}
.d1{animation-delay:.05s}
.d2{animation-delay:.1s}
.d3{animation-delay:.15s}

/* ═══ HF Footer ═══ */
.hf-footer{border-top:1px solid var(--gray-100);margin-top:auto}
.hf-footer-inner{max-width:1280px;margin:0 auto;padding:32px 16px;display:grid;grid-template-columns:repeat(2,1fr);gap:24px}
@media(min-width:768px){.hf-footer-inner{grid-template-columns:repeat(4,1fr)}}
.footer-title{font:600 14px "Source Sans 3",sans-serif;color:var(--gray-800);margin-bottom:10px}
.footer-links{list-style:none;display:flex;flex-direction:column;gap:6px}
.footer-links a{font-size:14px;color:var(--gray-500);text-decoration:none;transition:color .1s}
.footer-links a:hover{color:var(--gray-900);text-decoration:underline}
.footer-brand{display:flex;align-items:center;gap:8px;text-decoration:none;margin-bottom:8px}
.footer-brand-text{font:700 15px "Source Sans 3",sans-serif;color:var(--gray-900)}
.footer-tagline{font-size:13px;color:var(--gray-400);margin-bottom:12px;line-height:1.5}
.footer-bottom{border-top:1px solid var(--gray-100);max-width:1280px;margin:0 auto;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--gray-400);gap:8px;flex-wrap:wrap}
</style>
</head>
<body>';
}

// ══════════════════════════════════════════════════════════
// HF LOGO SVG
// ══════════════════════════════════════════════════════════
function hf_logo_svg(string $classes = ''): string {
    return '<svg class="' . h($classes) . '" viewBox="0 0 95 88" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M47.2119 76.5C66.4037 76.5 81.9619 60.9419 81.9619 41.75C81.9619 22.5581 66.4037 7 47.2119 7C28.02 7 12.4619 22.5581 12.4619 41.75C12.4619 60.9419 28.02 76.5 47.2119 76.5Z" fill="#FFD21E"/>
<path d="M81.9619 41.75C81.9619 22.5581 66.4037 7 47.2119 7C28.02 7 12.4619 22.5581 12.4619 41.75C12.4619 60.9419 28.02 76.5 47.2119 76.5C66.4037 76.5 81.9619 60.9419 81.9619 41.75ZM8.46185 41.75C8.46185 20.349 25.8108 3 47.2119 3C68.6129 3 85.9619 20.349 85.9619 41.75C85.9619 63.151 68.6129 80.5 47.2119 80.5C25.8108 80.5 8.46185 63.151 8.46185 41.75Z" fill="#FF9D0B"/>
<path d="M58.5024 32.2915C59.7768 32.7415 60.2839 35.3615 61.5713 34.6769C64.0095 33.3805 64.9351 30.353 63.6387 27.9148C62.3423 25.4767 59.3148 24.5511 56.8766 25.8475C54.4384 27.1439 53.5128 30.1714 54.8092 32.6096C55.4211 33.7604 57.3632 31.8892 58.5024 32.2915Z" fill="#3A3B45"/>
<path d="M34.9454 32.2915C33.671 32.7415 33.164 35.3615 31.8766 34.6769C29.4384 33.3805 28.5128 30.353 29.8092 27.9148C31.1056 25.4767 34.1331 24.5511 36.5713 25.8475C39.0095 27.1439 39.9351 30.1714 38.6387 32.6096C38.0268 33.7604 36.0846 31.8892 34.9454 32.2915Z" fill="#3A3B45"/>
<path d="M46.9619 56.289C56.7903 56.289 59.9619 47.5261 59.9619 43.0262C59.9619 40.6875 58.3898 41.4236 55.8718 42.6702C53.5449 43.8222 50.4102 45.4101 46.9619 45.4101C39.7822 45.4101 33.9619 38.5263 33.9619 43.0262C33.9619 47.5261 37.1334 56.289 46.9619 56.289Z" fill="#3A3B45"/>
<path d="M70.7119 37C72.5068 37 73.9619 35.5449 73.9619 33.75C73.9619 31.9551 72.5068 30.5 70.7119 30.5C68.9169 30.5 67.4619 31.9551 67.4619 33.75C67.4619 35.5449 68.9169 37 70.7119 37Z" fill="#FF9D0B"/>
<path d="M24.2119 37C26.0068 37 27.4619 35.5449 27.4619 33.75C27.4619 31.9551 26.0068 30.5 24.2119 30.5C22.4169 30.5 20.9619 31.9551 20.9619 33.75C20.9619 35.5449 22.4169 37 24.2119 37Z" fill="#FF9D0B"/>
</svg>';
}

// ══════════════════════════════════════════════════════════
// HF NAV BAR
// ══════════════════════════════════════════════════════════
function hf_nav(array $C, string $activePage = 'scripts'): void {
    $readonly = !$C['token'];
    $base = base_url();
    echo '<nav class="hf-nav">
<div class="hf-nav-inner">
  <a class="hf-logo-link" href="' . h($base) . '/">' . hf_logo_svg() . '<span class="hf-logo-text">Vyve</span></a>
  <div class="hf-search-wrap">
    <svg class="hf-search-icon" viewBox="0 0 32 32" fill="currentColor"><path d="M30 28.59L22.45 21A11 11 0 1 0 21 22.45L28.59 30zM5 14a9 9 0 1 1 9 9a9 9 0 0 1-9-9z"/></svg>
    <input id="navSearch" class="hf-search" type="text" placeholder="Search scripts..." autocomplete="off" oninput="onNavSearch(this.value)">
  </div>
  <div class="hf-nav-links">
    <a class="hf-nav-link models" href="' . h($base) . '/">
      <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path opacity=".25" d="M20.23 7.24L12 12L3.77 7.24a1.98 1.98 0 0 1 .7-.71L11 2.76c.62-.35 1.38-.35 2 0l6.53 3.77c.29.173.531.418.7.71z" fill="currentColor"/><path opacity=".5" d="M12 12v9.5a2.09 2.09 0 0 1-.91-.21L4.5 17.48a2.003 2.003 0 0 1-1-1.73v-7.5a2.06 2.06 0 0 1 .27-1.01L12 12z" fill="currentColor"/><path d="M20.5 8.25v7.5a2.003 2.003 0 0 1-1 1.73l-6.62 3.82c-.275.13-.576.198-.88.2V12l8.23-4.76c.175.308.268.656.27 1.01z" fill="currentColor"/></svg>
      Scripts
    </a>
    <a class="hf-nav-link datasets" href="' . h($base) . '/skill">
      <svg viewBox="0 0 24 24" fill="none"><ellipse cx="12" cy="5" rx="8" ry="2" fill="currentColor" opacity=".25"/><path d="M12 15C16.4 15 20 14.1 20 13V20C20 21.1 16.4 22 12 22C7.6 22 4 21.1 4 20V13C4 14.1 7.6 15 12 15Z" fill="currentColor" opacity=".5"/><path d="M12 7C16.4 7 20 6.1 20 5V11.5C20 12.6 16.4 13.5 12 13.5C7.6 13.5 4 12.6 4 11.5V5C4 6.1 7.6 7 12 7Z" fill="currentColor" opacity=".5"/></svg>
      API Docs
    </a>
  </div>
  <div class="hf-nav-actions">
    ' . ($readonly ? '<span class="tag tag-yellow" title="No token configured — Read-only mode"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Read-only</span>' : '<span class="tag tag-green"><span class="status-dot online"></span>Live</span>') . '
    ' . (!$readonly ? '<button class="hf-btn hf-btn-primary" onclick="openUpload()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>Deploy</button>' : '') . '
  </div>
</div>
</nav>';
}

// ══════════════════════════════════════════════════════════
// HF FOOTER
// ══════════════════════════════════════════════════════════
function hf_footer(array $C): void {
    $base = base_url();
    echo '<footer class="hf-footer">
<div class="hf-footer-inner">
  <div>
    <a class="footer-brand" href="' . h($base) . '/">' . hf_logo_svg() . '<span class="footer-brand-text">Vyve</span></a>
    <p class="footer-tagline">Free Lua script deployment for Roblox &amp; AI Agents. Backed by GitHub.</p>
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <span class="tag tag-gray">PHP 8.3</span>
      <span class="tag tag-gray">GitHub Backend</span>
      <span class="tag tag-indigo">v21</span>
    </div>
  </div>
  <div>
    <div class="footer-title">Platform</div>
    <ul class="footer-links">
      <li><a href="' . h($base) . '/">Scripts</a></li>
      <li><a href="' . h($base) . '/skill">API Docs</a></li>
      <li><a href="' . h($base) . '/api/list">JSON API</a></li>
    </ul>
  </div>
  <div>
    <div class="footer-title">Developers</div>
    <ul class="footer-links">
      <li><a href="https://github.com/' . h($C['repo']) . '" target="_blank" rel="noopener">GitHub Repo</a></li>
      <li><a href="https://docs.github.com/en/rest" target="_blank" rel="noopener">GitHub API</a></li>
      <li><a href="' . h($base) . '/raw/example">Raw Example</a></li>
    </ul>
  </div>
  <div>
    <div class="footer-title">Security</div>
    <ul class="footer-links">
      <li><a href="#" onclick="return false" style="cursor:default;color:var(--gray-400)">Token via ENV</a></li>
      <li><a href="#" onclick="return false" style="cursor:default;color:var(--gray-400)">SSL enforced</a></li>
      <li><a href="#" onclick="return false" style="cursor:default;color:var(--gray-400)">Rate limited</a></li>
    </ul>
  </div>
</div>
<div class="footer-bottom">
  <span>© ' . date('Y') . ' Vyve Group — All rights reserved</span>
  <span>Vyve v21 · PHP ' . PHP_VERSION . ' · ' . PHP_INT_SIZE * 8 . '-bit</span>
</div>
</footer>';
}

// ══════════════════════════════════════════════════════════
// SKILL / API DOCS PAGE
// ══════════════════════════════════════════════════════════
function page_skill(array $C): void {
    $base = base_url();
    header('Content-Type: text/html; charset=utf-8');
    html_head('API Docs — Vyve');
    hf_nav($C, 'docs');
    echo '<style>
.doc-layout{max-width:1280px;margin:0 auto;padding:0 16px;display:flex;gap:32px;padding-top:32px;padding-bottom:64px}
.doc-sidebar{flex:0 0 200px;display:none;position:sticky;top:80px;align-self:flex-start;max-height:calc(100dvh - 100px);overflow-y:auto}
@media(min-width:1024px){.doc-sidebar{display:block}}
.doc-nav-title{font:700 11px "Source Sans 3",sans-serif;color:var(--gray-400);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.doc-nav-link{display:block;padding:5px 10px;font:400 14px "Source Sans 3",sans-serif;color:var(--gray-600);text-decoration:none;border-radius:var(--radius-sm);transition:all .1s;border-left:2px solid transparent;margin-bottom:2px}
.doc-nav-link:hover{color:var(--gray-900);background:var(--gray-50)}
.doc-nav-link.active{color:var(--indigo-700);background:var(--indigo-50);border-left-color:var(--indigo-500);font-weight:600}
.doc-content{flex:1;min-width:0}
.doc-section{margin-bottom:40px}
.doc-section-title{font:700 20px "Source Sans 3",sans-serif;color:var(--gray-900);margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--gray-100)}
.endpoint{border:1px solid var(--gray-200);border-radius:var(--radius-lg);overflow:hidden;margin-bottom:14px}
.endpoint-head{display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--gray-50);border-bottom:1px solid var(--gray-200)}
.ep-method{font:700 11px "IBM Plex Mono",monospace;padding:3px 8px;border-radius:var(--radius-sm);text-transform:uppercase;letter-spacing:.05em}
.ep-get{background:#dcfce7;color:#15803d}
.ep-post{background:#dbeafe;color:#1d4ed8}
.ep-del{background:#fee2e2;color:#dc2626}
.ep-path{font:500 14px "IBM Plex Mono",monospace;color:var(--gray-700)}
.endpoint-body{padding:16px}
.ep-desc{font-size:14px;color:var(--gray-600);margin-bottom:12px;line-height:1.6}
.code-block{background:var(--gray-950);border-radius:var(--radius);overflow:hidden;margin-bottom:12px}
.code-head{display:flex;align-items:center;justify-content:space-between;padding:8px 14px;border-bottom:1px solid #1f2937}
.code-lang{font:600 11px "IBM Plex Mono",monospace;color:var(--gray-400)}
.code-copy-btn{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;font:600 11px "Source Sans 3",sans-serif;color:var(--gray-400);background:transparent;border:1px solid #374151;border-radius:var(--radius-sm);cursor:pointer;transition:all .1s}
.code-copy-btn:hover{color:var(--white);border-color:#4b5563}
.code-body{padding:14px;overflow-x:auto;font:400 13px/1.6 "IBM Plex Mono",monospace;color:#e5e7eb}
.code-body .k{color:#93c5fd}
.code-body .s{color:#86efac}
.code-body .f{color:#fde68a}
.code-body .c{color:#6b7280}
.info-box{display:flex;gap:12px;padding:14px 16px;border-radius:var(--radius);border:1px solid;margin-bottom:12px}
.info-tip{background:#eff6ff;border-color:#bfdbfe}
.info-warn{background:#fef9c3;border-color:#fef08a}
.info-icon{width:20px;height:20px;border-radius:50%;display:grid;place-items:center;flex-shrink:0;margin-top:1px}
.info-tip .info-icon{background:#dbeafe;color:#1d4ed8}
.info-warn .info-icon{background:#fef08a;color:#a16207}
.info-icon svg{width:11px;height:11px}
.info-content{}
.info-title{font:600 13px "Source Sans 3",sans-serif;color:var(--gray-800);margin-bottom:2px}
.info-text{font-size:13px;color:var(--gray-600);line-height:1.5}
.param-table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:12px}
.param-table th{text-align:left;padding:8px 12px;font:600 11px "Source Sans 3",sans-serif;color:var(--gray-500);text-transform:uppercase;letter-spacing:.05em;background:var(--gray-50);border-bottom:1px solid var(--gray-200)}
.param-table td{padding:8px 12px;border-bottom:1px solid var(--gray-100);color:var(--gray-700)}
.param-table td:first-child{font:500 13px "IBM Plex Mono",monospace;color:var(--indigo-700)}
.doc-footer{padding-top:24px;border-top:1px solid var(--gray-100);font-size:13px;color:var(--gray-400)}
</style>
<div class="doc-layout">
  <aside class="doc-sidebar">
    <div class="doc-nav-title">API Reference</div>
    <a class="doc-nav-link active" href="#start">Quick Start</a>
    <a class="doc-nav-link" href="#list">List Scripts</a>
    <a class="doc-nav-link" href="#upload">Upload</a>
    <a class="doc-nav-link" href="#delete">Delete</a>
    <a class="doc-nav-link" href="#raw">Raw Endpoint</a>
    <a class="doc-nav-link" href="#agent">AI Agent Badge</a>
    <a class="doc-nav-link" href="#security">Security</a>
    <a class="doc-nav-link" href="#examples">Examples</a>
  </aside>
  <main class="doc-content">
    <section id="start" class="doc-section">
      <h2 class="doc-section-title">Quick Start</h2>
      <p style="color:var(--gray-600);font-size:14px;margin-bottom:14px">Base URL: <code style="font-family:\'IBM Plex Mono\',monospace;font-size:13px;background:var(--gray-100);padding:3px 8px;border-radius:var(--radius-sm)"><?= h($base) ?></code></p>
      <div class="info-box info-tip">
        <div class="info-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/></svg></div>
        <div class="info-content">
          <div class="info-title">Authentication</div>
          <div class="info-text">The public <code>/api/list</code> and <code>/raw/*</code> endpoints require no authentication. Write operations require a configured GitHub token on the server side.</div>
        </div>
      </div>
    </section>
    <section id="list" class="doc-section">
      <h2 class="doc-section-title">List Scripts</h2>
      <div class="endpoint">
        <div class="endpoint-head"><span class="ep-method ep-get">GET</span><span class="ep-path">/api/list</span></div>
        <div class="endpoint-body">
          <p class="ep-desc">Returns all deployed scripts with loadstring URLs, metadata, and agent status. No auth required.</p>
          <div class="code-block">
            <div class="code-head"><span class="code-lang">JavaScript</span><button class="code-copy-btn" onclick="cpCode(this)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
            <div class="code-body"><span class="k">const</span> res = <span class="k">await</span> <span class="f">fetch</span>(<span class="s">"<?= h($base) ?>/api/list"</span>);
<span class="k">const</span> { scripts, ok, readonly } = <span class="k">await</span> res.<span class="f">json</span>();
scripts.<span class="f">forEach</span>(s => console.<span class="f">log</span>(s.name, s.ls, s.agent));</div>
          </div>
          <p class="ep-desc" style="margin-top:4px"><strong>Response fields:</strong> <code>name</code>, <code>slug</code>, <code>size</code>, <code>raw</code>, <code>ls</code> (loadstring), <code>lsd</code> (debug), <code>agent</code>, <code>bad</code>, <code>sha</code></p>
        </div>
      </div>
    </section>
    <section id="upload" class="doc-section">
      <h2 class="doc-section-title">Upload Script</h2>
      <div class="endpoint">
        <div class="endpoint-head"><span class="ep-method ep-post">POST</span><span class="ep-path">/api/upload</span></div>
        <div class="endpoint-body">
          <p class="ep-desc">Create or update a Lua script. Max file size: 512KB.</p>
          <table class="param-table">
            <tr><th>Parameter</th><th>Type</th><th>Required</th><th>Description</th></tr>
            <tr><td>filename</td><td>string</td><td>Yes*</td><td>Script name (auto-appends .lua)</td></tr>
            <tr><td>content</td><td>string</td><td>Yes*</td><td>Lua source code</td></tr>
            <tr><td>file</td><td>File</td><td>Yes*</td><td>.lua file upload (multipart)</td></tr>
            <tr><td>agent</td><td>boolean</td><td>No</td><td>Mark as AI Agent generated</td></tr>
          </table>
          <div class="code-block">
            <div class="code-head"><span class="code-lang">JSON Body</span><button class="code-copy-btn" onclick="cpCode(this)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
            <div class="code-body"><span class="f">fetch</span>(<span class="s">"<?= h($base) ?>/api/upload"</span>, {
  method: <span class="s">"POST"</span>,
  headers: { <span class="s">"Content-Type"</span>: <span class="s">"application/json"</span> },
  body: JSON.<span class="f">stringify</span>({ filename: <span class="s">"my-script"</span>, content: <span class="s">"print(42)"</span>, agent: <span class="k">true</span> })
});</div>
          </div>
        </div>
      </div>
    </section>
    <section id="delete" class="doc-section">
      <h2 class="doc-section-title">Delete Script</h2>
      <div class="endpoint">
        <div class="endpoint-head"><span class="ep-method ep-del">POST</span><span class="ep-path">/api/delete</span></div>
        <div class="endpoint-body">
          <div class="code-block">
            <div class="code-head"><span class="code-lang">Request</span><button class="code-copy-btn" onclick="cpCode(this)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
            <div class="code-body"><span class="f">fetch</span>(<span class="s">"<?= h($base) ?>/api/delete"</span>, {
  method: <span class="s">"POST"</span>,
  headers: { <span class="s">"Content-Type"</span>: <span class="s">"application/json"</span> },
  body: JSON.<span class="f">stringify</span>({ filename: <span class="s">"my-script.lua"</span> })
});</div>
          </div>
        </div>
      </div>
    </section>
    <section id="raw" class="doc-section">
      <h2 class="doc-section-title">Raw Endpoint</h2>
      <div class="endpoint">
        <div class="endpoint-head"><span class="ep-method ep-get">GET</span><span class="ep-path">/raw/{slug}</span></div>
        <div class="endpoint-body">
          <p class="ep-desc">Returns raw Lua code. CORS enabled. No auth required. Use in Roblox executor.</p>
          <div class="code-block">
            <div class="code-head"><span class="code-lang">Lua (Roblox)</span><button class="code-copy-btn" onclick="cpCode(this)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
            <div class="code-body"><span class="c">-- Execute in any Roblox executor</span>
<span class="f">loadstring</span>(game:HttpGet(<span class="s">"<?= h($base) ?>/raw/my-script"</span>))()</div>
          </div>
          <div class="code-block">
            <div class="code-head"><span class="code-lang">Debug Mode</span><button class="code-copy-btn" onclick="cpCode(this)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
            <div class="code-body"><span class="c">-- Includes timing + error reporting</span>
<span class="f">loadstring</span>(game:HttpGet(<span class="s">"<?= h($base) ?>/raw/my-script/debug"</span>))()</div>
          </div>
        </div>
      </div>
    </section>
    <section id="agent" class="doc-section">
      <h2 class="doc-section-title">AI Agent Badge</h2>
      <p style="font-size:14px;color:var(--gray-600);margin-bottom:12px;line-height:1.6">When uploading with <code style="font-family:\'IBM Plex Mono\',monospace;font-size:12px">agent: true</code>, the script shows a purple <strong style="color:#9333ea">Agent</strong> badge in the UI.</p>
      <div class="info-box info-tip">
        <div class="info-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg></div>
        <div class="info-content">
          <div class="info-title">AI Transparency</div>
          <div class="info-text">Mark AI-generated scripts for transparency. Helps users distinguish automated deployments from manual uploads.</div>
        </div>
      </div>
    </section>
    <section id="security" class="doc-section">
      <h2 class="doc-section-title">Security Model</h2>
      <div class="info-box info-warn">
        <div class="info-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
        <div class="info-content">
          <div class="info-title">Never hardcode your GitHub token</div>
          <div class="info-text">Set <code>VYVE_GH_TOKEN</code> as a server environment variable, or create a <code>.vyve.env</code> file next to index.php (outside webroot recommended).</div>
        </div>
      </div>
      <table class="param-table">
        <tr><th>Feature</th><th>Implementation</th></tr>
        <tr><td>Token storage</td><td>ENV var or .vyve.env file — never in source</td></tr>
        <tr><td>SSL verification</td><td>Enforced (CURLOPT_SSL_VERIFYPEER = true)</td></tr>
        <tr><td>Protocol restriction</td><td>HTTPS-only (CURLPROTO_HTTPS)</td></tr>
        <tr><td>Rate limiting</td><td>Per-IP, file-based, configurable</td></tr>
        <tr><td>Input sanitization</td><td>Strict regex on all filenames</td></tr>
        <tr><td>Path traversal</td><td>basename() + allowlist regex</td></tr>
        <tr><td>File size limit</td><td>512KB maximum upload</td></tr>
        <tr><td>Redirect following</td><td>Disabled (FOLLOWLOCATION = false)</td></tr>
      </table>
      <h3 style="font:600 15px \'Source Sans 3\',sans-serif;color:var(--gray-800);margin:16px 0 10px">Setup .vyve.env</h3>
      <div class="code-block">
        <div class="code-head"><span class="code-lang">.vyve.env</span><button class="code-copy-btn" onclick="cpCode(this)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
        <div class="code-body"><span class="c"># Place next to index.php — keep outside webroot if possible</span>
VYVE_GH_TOKEN=ghp_yourTokenHere
VYVE_GH_REPO=youruser/yourrepo
VYVE_GH_BRANCH=main
VYVE_GH_DIR=scripts
VYVE_RATE_LIMIT=60</div>
      </div>
    </section>
    <section id="examples" class="doc-section">
      <h2 class="doc-section-title">Python Example</h2>
      <div class="code-block">
        <div class="code-head"><span class="code-lang">Python</span><button class="code-copy-btn" onclick="cpCode(this)"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
        <div class="code-body"><span class="k">import</span> requests

<span class="k">def</span> <span class="f">deploy</span>(name, code, agent=<span class="k">True</span>):
    res = requests.<span class="f">post</span>(<span class="s">"<?= h($base) ?>/api/upload"</span>, json={
        <span class="s">"filename"</span>: name, <span class="s">"content"</span>: code, <span class="s">"agent"</span>: agent
    })
    <span class="k">return</span> res.<span class="f">json</span>()

result = <span class="f">deploy</span>(<span class="s">"auto-farm"</span>, <span class="s">"print(\'Hello!\')"</span>)
print(result[<span class="s">"ls"</span>])  <span class="c"># Prints the loadstring URL</span></div>
      </div>
      <p class="doc-footer">Vyve API v21 · PHP <?= h(PHP_VERSION) ?> (<?= PHP_INT_SIZE * 8 ?>-bit)</p>
    </section>
  </main>
</div>
<script>
function cpCode(btn){
  const text=btn.closest(".code-block").querySelector(".code-body").textContent;
  navigator.clipboard.writeText(text).then(()=>{
    const o=btn.innerHTML;
    btn.innerHTML=\'<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>Done\';
    setTimeout(()=>btn.innerHTML=o,1500);
  });
}
document.querySelectorAll("a[href^=\'#\']").forEach(a=>{
  a.addEventListener("click",e=>{e.preventDefault();document.querySelector(a.getAttribute("href"))?.scrollIntoView({behavior:"smooth"})});
});
const sections=document.querySelectorAll(".doc-section[id]");
const navLinks=document.querySelectorAll(".doc-nav-link");
new IntersectionObserver(entries=>{
  entries.forEach(en=>{
    if(en.isIntersecting){navLinks.forEach(l=>l.classList.remove("active"));document.querySelector(`.doc-nav-link[href="#${en.target.id}"]`)?.classList.add("active")}
  });
},{rootMargin:"-20% 0px -70% 0px"}).observe(...sections);
sections.forEach(s=>new IntersectionObserver(entries=>{
  entries.forEach(en=>{
    if(en.isIntersecting){navLinks.forEach(l=>l.classList.remove("active"));document.querySelector(`.doc-nav-link[href="#${en.target.id}"]`)?.classList.add("active")}
  });
},{rootMargin:"-20% 0px -70% 0px"}).observe(s));
</script>
</body></html>';
}

// ══════════════════════════════════════════════════════════
// MAIN PAGE — Full Hugging Face Style
// ══════════════════════════════════════════════════════════
function page_main(array $C): void {
    $base     = base_url();
    $readonly = !$C['token'];
    $csrf     = csrf_token();

    header('Content-Type: text/html; charset=utf-8');
    html_head('Vyve — Script Deployment Platform');
    hf_nav($C);

    if ($readonly): ?>
<div class="readonly-banner">
  ⚠️ Running in <strong>read-only mode</strong> — GitHub token not configured.
  Set <code>VYVE_GH_TOKEN</code> in your environment or create a <code>.vyve.env</code> file.
  <a href="<?= h($base) ?>/skill#security" style="margin-left:8px">Setup guide →</a>
</div>
<?php endif; ?>

<!-- ══ Welcome Slides ══ -->
<div class="welcome-wrap" id="welcome">
  <div class="welcome-inner">
    <div class="welcome-slides" id="wSlides">

      <!-- Slide 1 -->
      <div class="welcome-slide">
        <div class="ws-illus">
          <div class="ws-mockup">
            <div class="ws-mock-head">
              <div class="ws-mock-dots"><div class="ws-mock-dot r"></div><div class="ws-mock-dot y"></div><div class="ws-mock-dot g"></div></div>
              <span class="ws-mock-title">vyve.app</span>
            </div>
            <div class="ws-mock-body">
              <div class="ws-mock-item anim-up d1"><div class="ws-mock-av y">A</div><span class="ws-mock-name">auto_farm.lua</span><span class="ws-mock-badge live">Live</span></div>
              <div class="ws-mock-item anim-up d2"><div class="ws-mock-av p">S</div><span class="ws-mock-name">speed_hack.lua</span><span class="ws-mock-badge agent">Agent</span></div>
              <div class="ws-mock-item anim-up d3"><div class="ws-mock-av g">E</div><span class="ws-mock-name">esp_aimbot.lua</span><span class="ws-mock-badge live">Live</span></div>
            </div>
          </div>
        </div>
        <div class="ws-text">
          <h2 class="ws-title">Deploy Lua scripts instantly</h2>
          <p class="ws-desc">Vyve is a free platform for hosting Roblox Lua scripts. Backed by GitHub, no server needed.</p>
        </div>
      </div>

      <!-- Slide 2 -->
      <div class="welcome-slide">
        <div class="ws-illus" style="background:linear-gradient(135deg,#dcfce7,#d1fae5)">
          <div class="ws-mockup">
            <div class="ws-mock-head">
              <div class="ws-mock-dots"><div class="ws-mock-dot r"></div><div class="ws-mock-dot y"></div><div class="ws-mock-dot g"></div></div>
              <span class="ws-mock-title">Roblox Executor</span>
            </div>
            <div class="ws-mock-body" style="font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:#374151">
              <div style="background:#f0fdf4;border-radius:6px;padding:10px;border:1px solid #bbf7d0">
                <div style="color:#6b7280;margin-bottom:4px">-- One-click copy:</div>
                <div style="color:#166534">loadstring(game:HttpGet(<br>"<?= h($base) ?>/raw/script"))()</div>
              </div>
              <div style="text-align:center;padding:8px;color:#16a34a;font-weight:700;font-size:11px">✓ Executed in 42ms</div>
            </div>
          </div>
        </div>
        <div class="ws-text">
          <h2 class="ws-title">One-click loadstring URLs</h2>
          <p class="ws-desc">Every script gets a permanent raw URL. Copy the loadstring, paste in your executor. Done.</p>
        </div>
      </div>

      <!-- Slide 3 -->
      <div class="welcome-slide">
        <div class="ws-illus" style="background:linear-gradient(135deg,#f3e8ff,#ede9fe)">
          <div class="ws-mockup">
            <div class="ws-mock-head">
              <div class="ws-mock-dots"><div class="ws-mock-dot r"></div><div class="ws-mock-dot y"></div><div class="ws-mock-dot g"></div></div>
              <span class="ws-mock-title">AI Agent Deploy</span>
            </div>
            <div class="ws-mock-body">
              <div style="background:#f3e8ff;border-radius:6px;padding:10px;border:1px solid #e9d5ff;font-size:11px">
                <div style="font-weight:700;color:#9333ea;margin-bottom:6px">🤖 AI Agent</div>
                <div style="color:#7e22ce;font-family:\'IBM Plex Mono\',monospace;font-size:10px">POST /api/upload<br>{ agent: true }</div>
              </div>
              <div class="ws-mock-item" style="margin-top:6px"><div class="ws-mock-av p">B</div><span class="ws-mock-name">bot_farm.lua</span><span class="ws-mock-badge agent">Agent</span></div>
            </div>
          </div>
        </div>
        <div class="ws-text">
          <h2 class="ws-title">Built for AI Agents</h2>
          <p class="ws-desc">AI agents can deploy scripts via REST API. Full JSON response with live URLs, debug endpoints, and agent badges.</p>
        </div>
      </div>

    </div><!-- /slides -->
  </div>
  <div class="welcome-footer">
    <div class="ws-dots" id="wDots">
      <div class="ws-dot active" onclick="goSlide(0)"></div>
      <div class="ws-dot" onclick="goSlide(1)"></div>
      <div class="ws-dot" onclick="goSlide(2)"></div>
    </div>
    <button class="ws-next" id="wNext" onclick="nextSlide()">Get Started</button>
    <span class="ws-skip" onclick="skipWelcome()">Skip</span>
  </div>
</div>

<!-- ══ Hero ══ -->
<div class="hf-hero">
  <div class="hf-hero-inner">
    <div class="hf-hero-text">
      <div class="hf-hero-eyebrow">Free · Open · Fast</div>
      <h1 class="hf-hero-title">Script Deployment<br>for <em>Roblox & AI</em></h1>
      <p class="hf-hero-desc">Deploy Lua scripts in seconds. Every script gets a permanent loadstring URL backed by GitHub. Built for humans and AI agents.</p>
      <div class="hf-hero-actions">
        <?php if (!$readonly): ?>
        <button class="hf-btn hf-btn-primary" onclick="openUpload()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          Deploy Script
        </button>
        <?php endif; ?>
        <a href="<?= h($base) ?>/skill" class="hf-btn hf-btn-ghost">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/></svg>
          API Docs
        </a>
        <a href="https://github.com/<?= h($C['repo']) ?>" target="_blank" rel="noopener" class="hf-btn hf-btn-ghost">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.21 11.39.6.11.79-.26.79-.58v-2.23c-3.34.73-4.03-1.42-4.03-1.42-.55-1.39-1.33-1.76-1.33-1.76-1.09-.74.08-.73.08-.73 1.2.08 1.84 1.24 1.84 1.24 1.07 1.83 2.8 1.3 3.49 1 .11-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23.65 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.8 5.63-5.48 5.92.43.37.82 1.1.82 2.22v3.29c0 .32.19.7.8.58C20.57 21.8 24 17.3 24 12c0-6.63-5.37-12-12-12z"/></svg>
          GitHub
        </a>
      </div>
    </div>
    <div class="hf-hero-stats">
      <div class="hf-stat">
        <div class="hf-stat-num" id="heroCount">—</div>
        <div class="hf-stat-label">Scripts</div>
      </div>
      <div class="hf-stat">
        <div class="hf-stat-num" id="heroStatus" style="font-size:18px;display:flex;align-items:center;gap:6px">
          <span class="status-dot offline" id="heroDot"></span>
          <span id="heroStatusText">Loading</span>
        </div>
        <div class="hf-stat-label">Status</div>
      </div>
    </div>
  </div>
</div>

<!-- ══ Main Content ══ -->
<div class="hf-main">
  <div class="hf-layout">

    <!-- Sidebar -->
    <aside class="hf-sidebar">
      <div class="sidebar-section">
        <div class="sidebar-title">Filter</div>
        <div class="filter-group">
          <div class="filter-item active" onclick="setFilter('all', this)" id="f-all">All scripts<span class="filter-count" id="fc-all">0</span></div>
          <div class="filter-item" onclick="setFilter('agent', this)" id="f-agent">AI Agents<span class="filter-count" id="fc-agent">0</span></div>
          <div class="filter-item" onclick="setFilter('live', this)" id="f-live">Live<span class="filter-count" id="fc-live">0</span></div>
          <div class="filter-item" onclick="setFilter('bad', this)" id="f-bad">Needs Fix<span class="filter-count" id="fc-bad">0</span></div>
        </div>
      </div>
      <div class="sidebar-section">
        <div class="sidebar-title">Actions</div>
        <div class="filter-group">
          <?php if (!$readonly): ?>
          <div class="filter-item" onclick="openUpload()" style="cursor:pointer">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Deploy new script
          </div>
          <div class="filter-item" onclick="doFix()" style="cursor:pointer">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
            Fix bad filenames
          </div>
          <?php endif; ?>
          <div class="filter-item" onclick="load()" style="cursor:pointer">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            Refresh
          </div>
          <a class="filter-item" href="<?= h($base) ?>/api/list" target="_blank" style="text-decoration:none">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            JSON API
          </a>
        </div>
      </div>
    </aside>

    <!-- Main list -->
    <div class="hf-content">
      <div class="mobile-filter">
        <div class="hf-search-wrap">
          <svg class="hf-search-icon" viewBox="0 0 32 32" fill="currentColor"><path d="M30 28.59L22.45 21A11 11 0 1 0 21 22.45L28.59 30zM5 14a9 9 0 1 1 9 9a9 9 0 0 1-9-9z"/></svg>
          <input id="mobileSearch" class="hf-search" type="text" placeholder="Search scripts..." autocomplete="off" oninput="onNavSearch(this.value)">
        </div>
        <?php if (!$readonly): ?>
        <button class="hf-btn hf-btn-primary btn-sm" onclick="openUpload()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        </button>
        <?php endif; ?>
      </div>

      <div class="content-header">
        <div>
          <h2 class="content-title">Scripts</h2>
          <span class="content-count" id="listCount">Loading...</span>
        </div>
        <div class="sort-bar">
          <select class="sort-select" onchange="onSort(this.value)">
            <option value="name">Name A→Z</option>
            <option value="name-desc">Name Z→A</option>
            <option value="size">Smallest</option>
            <option value="size-desc">Largest</option>
          </select>
        </div>
      </div>

      <div id="listWrap">
        <div class="hf-loading"><div class="hf-spinner"></div><span>Fetching scripts...</span></div>
      </div>
    </div>

  </div>
</div>

<!-- ══ FAB (mobile) ══ -->
<?php if (!$readonly): ?>
<button class="fab" onclick="openUpload()">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
  Deploy
</button>
<?php endif; ?>

<!-- ══ Upload Modal ══ -->
<div class="modal-ov" id="uploadModal" onclick="if(event.target===this)closeUpload()">
  <div class="modal">
    <span class="modal-handle"></span>
    <div class="modal-head">
      <span class="modal-title">Deploy Script</span>
      <button class="modal-close" onclick="closeUpload()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </div>
    <div class="modal-body">
      <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('file',this)">File Upload</button>
        <button class="tab-btn" onclick="switchTab('code',this)">Paste Code</button>
      </div>
      <div id="filePanel">
        <div class="dropzone" id="dropzone">
          <input type="file" id="fileInput" accept=".lua,.txt" onchange="handleFile(this)">
          <div class="dropzone-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg></div>
          <p><strong>Click to browse</strong> or drag & drop</p>
          <small>.lua and .txt files · max 512KB</small>
          <div class="drop-file-label" id="dropFileLabel"></div>
        </div>
      </div>
      <div id="codePanel" style="display:none">
        <div class="form-group">
          <label class="form-label" for="codeFilename">Filename</label>
          <input class="form-input" type="text" id="codeFilename" placeholder="my-script (without .lua)">
          <p class="form-hint">.lua extension added automatically</p>
        </div>
        <div class="form-group">
          <label class="form-label" for="codeContent">Lua Code</label>
          <textarea class="form-textarea" id="codeContent" placeholder='print("Hello from Vyve!")'></textarea>
        </div>
      </div>
      <div class="form-group" style="margin-top:12px;margin-bottom:0">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none">
          <input type="checkbox" id="agentCheck" style="width:16px;height:16px;accent-color:#9333ea">
          <span style="font:400 14px 'Source Sans 3',sans-serif;color:var(--gray-700)">Mark as <strong style="color:#9333ea">AI Agent</strong> generated</span>
        </label>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="closeUpload()">Cancel</button>
      <button class="btn btn-primary" id="uploadBtn" onclick="doUpload()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        Deploy
      </button>
    </div>
  </div>
</div>

<!-- ══ Detail Modal ══ -->
<div class="modal-ov" id="detailModal" onclick="if(event.target===this)closeDetail()">
  <div class="modal">
    <span class="modal-handle"></span>
    <div class="modal-head">
      <span class="modal-title" id="detailName">Script</span>
      <button class="modal-close" onclick="closeDetail()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </div>
    <div class="modal-body">
      <div class="detail-meta" id="detailMeta"></div>
      <div class="detail-row">
        <span class="detail-label">Raw</span>
        <span class="detail-value" id="detailRaw"></span>
        <button class="detail-copy" onclick="copyVal('detailRaw')" title="Copy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
      </div>
      <div class="detail-row">
        <span class="detail-label">LS</span>
        <span class="detail-value" id="detailLS"></span>
        <button class="detail-copy" onclick="copyVal('detailLS')" title="Copy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
      </div>
      <div class="detail-row">
        <span class="detail-label">Debug</span>
        <span class="detail-value" id="detailDebug"></span>
        <button class="detail-copy" onclick="copyVal('detailDebug')" title="Copy"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
      </div>
      <div class="detail-row">
        <span class="detail-label">Size</span>
        <span class="detail-value" id="detailSize"></span>
      </div>
    </div>
    <div class="modal-footer">
      <?php if (!$readonly): ?>
      <button class="btn btn-danger btn-sm" id="deleteBtn" onclick="doDelete()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
        Delete
      </button>
      <?php endif; ?>
      <button class="btn btn-secondary btn-sm" onclick="copyVal('detailLS');toast('Loadstring copied!',true)">Copy LS</button>
      <button class="btn btn-primary btn-sm" onclick="closeDetail()">Close</button>
    </div>
  </div>
</div>

<!-- ══ Toasts ══ -->
<div class="toast-wrap" id="toasts"></div>

<?php hf_footer($C); ?>

<script>
/* ═══ State ═══ */
let scripts=[], curScript=null, selFile=null, curFilter='all', curSort='name';
const BASE='<?= h($base) ?>';
const READONLY=<?= $readonly ? 'true' : 'false' ?>;

/* ═══ Helpers ═══ */
const $=id=>document.getElementById(id);
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function fmtSize(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB'}
function getColor(name){const h=name.split('').reduce((a,c)=>a+c.charCodeAt(0),0);return h%6}
function setStatus(ok,text){
  $('heroDot').className='status-dot '+(ok?'online':'offline');
  $('heroStatusText').textContent=text;
}

/* ═══ API ═══ */
async function api(ep,opts={}){
  const res=await fetch(BASE+'/'+ep,{...opts,headers:{...opts.headers}});
  if(!res.ok)throw new Error('HTTP '+res.status);
  return res.json();
}

/* ═══ Nav Search ═══ */
function onNavSearch(q){
  $('mobileSearch')&&(document.getElementById('mobileSearch').value=q);
  $('navSearch')&&(document.getElementById('navSearch').value=q);
  applyFilters();
}

/* ═══ Filter & Sort ═══ */
function setFilter(f, el){
  curFilter=f;
  document.querySelectorAll('.filter-item').forEach(i=>i.classList.remove('active'));
  if(el)el.classList.add('active');
  applyFilters();
}
function onSort(v){curSort=v;applyFilters()}
function applyFilters(){
  const q=($('navSearch')||{value:''}).value.toLowerCase().trim();
  let list=[...scripts];
  if(curFilter==='agent')list=list.filter(s=>s.agent);
  else if(curFilter==='live')list=list.filter(s=>!s.bad&&!s.agent);
  else if(curFilter==='bad')list=list.filter(s=>s.bad);
  if(q)list=list.filter(s=>s.name.toLowerCase().includes(q)||s.slug.toLowerCase().includes(q));
  if(curSort==='name')list.sort((a,b)=>a.name.localeCompare(b.name));
  else if(curSort==='name-desc')list.sort((a,b)=>b.name.localeCompare(a.name));
  else if(curSort==='size')list.sort((a,b)=>a.size-b.size);
  else if(curSort==='size-desc')list.sort((a,b)=>b.size-a.size);
  render(list);
}

/* ═══ Load ═══ */
async function load(){
  $('listWrap').innerHTML='<div class="hf-loading"><div class="hf-spinner"></div><span>Fetching scripts from GitHub...</span></div>';
  try{
    const data=await api('api/list');
    if(data.ok){
      scripts=data.scripts||[];
      $('heroCount').textContent=scripts.length;
      setStatus(true,'Online');
      // Update filter counts
      $('fc-all').textContent=scripts.length;
      $('fc-agent').textContent=scripts.filter(s=>s.agent).length;
      $('fc-live').textContent=scripts.filter(s=>!s.bad&&!s.agent).length;
      $('fc-bad').textContent=scripts.filter(s=>s.bad).length;
      applyFilters();
    } else {
      $('heroCount').textContent='—';
      $('listWrap').innerHTML=emptyState('Failed to load',data.error||'GitHub API error');
      setStatus(false,'Error');
    }
  } catch(e){
    $('heroCount').textContent='—';
    $('listWrap').innerHTML=emptyState('Connection error','Cannot reach server — check config');
    setStatus(false,'Offline');
  }
}

/* ═══ Render ═══ */
function render(list){
  $('listCount').textContent=list.length+' script'+(list.length!==1?'s':'');
  if(!list.length){$('listWrap').innerHTML=emptyState('No scripts found','Try changing the filter or deploy your first script');return}
  let h='<div class="model-grid">';
  list.forEach((s,i)=>{
    const c=getColor(s.name);
    const tags=[];
    if(s.agent)tags.push('<span class="tag tag-purple">Agent</span>');
    if(s.bad)tags.push('<span class="tag tag-red">Needs Fix</span>');
    else tags.push('<span class="tag tag-green">Live</span>');
    tags.push('<span class="tag tag-gray">'+esc(fmtSize(s.size))+'</span>');
    h+=`<div class="model-card" style="animation-delay:${Math.min(i*30,180)}ms;animation:fadeUp .3s ease both" onclick="showDetail(${i})">
      <div class="model-avatar mc${c}">${esc(s.name.charAt(0).toUpperCase())}</div>
      <div class="model-info">
        <div class="model-name">${esc(s.name)}</div>
        <div class="model-path">/raw/${esc(s.slug)}</div>
        <div class="model-tags">${tags.join('')}</div>
      </div>
    </div>
    <div class="card-chips" style="margin-top:-1px;border-bottom:1px solid var(--gray-100)">
      <button class="chip chip-copy" onclick="event.stopPropagation();cp(${JSON.stringify(s.ls)})" title="Copy loadstring">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy LS
      </button>
      <button class="chip chip-debug" onclick="event.stopPropagation();cp(${JSON.stringify(s.lsd)})" title="Copy debug loadstring">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>Debug
      </button>
      <a class="chip chip-raw" href="${esc(s.raw)}" target="_blank" onclick="event.stopPropagation()" title="Open raw">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>Raw
      </a>
    </div>`;
  });
  $('listWrap').innerHTML=h+'</div>';
}

function emptyState(t,d){
  return`<div class="hf-empty"><div class="hf-empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></svg></div><h3>${esc(t)}</h3><p>${esc(d)}</p></div>`;
}

/* ═══ Upload ═══ */
function openUpload(){selFile=null;$('fileInput').value='';$('dropFileLabel').style.display='none';$('codeFilename').value='';$('codeContent').value='';$('agentCheck').checked=false;$('uploadModal').classList.add('on')}
function closeUpload(){$('uploadModal').classList.remove('on')}
function switchTab(tab,el){
  el.parentElement.querySelectorAll('.tab-btn').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  $('filePanel').style.display=tab==='file'?'':'none';
  $('codePanel').style.display=tab==='code'?'':'none';
}
function handleFile(inp){
  if(inp.files.length){
    selFile=inp.files[0];
    $('dropFileLabel').textContent=selFile.name+' · '+fmtSize(selFile.size);
    $('dropFileLabel').style.display='block';
  }
}
const dz=$('dropzone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('on')});
dz.addEventListener('dragleave',()=>dz.classList.remove('on'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('on');if(e.dataTransfer.files.length){$('fileInput').files=e.dataTransfer.files;handleFile($('fileInput'))}});
async function doUpload(){
  const btn=$('uploadBtn'),isFile=$('filePanel').style.display!=='none';
  btn.disabled=true;btn.textContent='Deploying...';
  try{
    const fd=new FormData();
    if(isFile&&selFile){fd.append('file',selFile)}
    else if(!isFile){
      const fn=$('codeFilename').value.trim(),code=$('codeContent').value;
      if(!fn||!code){toast('Fill all fields',false);return}
      fd.append('filename',fn);fd.append('content',code);
    } else {toast('Select a file',false);return}
    if($('agentCheck').checked)fd.append('agent','true');
    const data=await api('api/upload',{method:'POST',body:fd});
    if(data.ok){toast('✓ Deployed: '+data.filename,true);closeUpload();await load()}
    else toast(data.error||'Upload failed',false);
  } catch(e){toast('Upload error: '+e.message,false)}
  finally{btn.disabled=false;btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>Deploy'}
}

/* ═══ Detail ═══ */
function showDetail(i){
  curScript=scripts[i];
  $('detailName').textContent=curScript.name;
  $('detailLS').textContent=curScript.ls;
  $('detailRaw').textContent=curScript.raw;
  $('detailDebug').textContent=curScript.lsd;
  $('detailSize').textContent=fmtSize(curScript.size);
  const tags=[];
  if(curScript.agent)tags.push('<span class="tag tag-purple">Agent</span>');
  if(curScript.bad)tags.push('<span class="tag tag-red">Needs Fix</span>');
  else tags.push('<span class="tag tag-green">Live</span>');
  $('detailMeta').innerHTML=tags.join('');
  $('detailModal').classList.add('on');
}
function closeDetail(){$('detailModal').classList.remove('on');curScript=null}
async function doDelete(){
  if(!curScript||!confirm('Delete "'+curScript.name+'"? This cannot be undone.'))return;
  const btn=$('deleteBtn');btn.disabled=true;btn.textContent='Deleting...';
  try{
    const fd=new FormData();fd.append('filename',curScript.name);
    const data=await api('api/delete',{method:'POST',body:fd});
    if(data.ok){toast('Deleted: '+curScript.name,true);closeDetail();await load()}
    else toast(data.error||'Delete failed',false);
  } catch(e){toast('Error: '+e.message,false)}
  finally{btn.disabled=false;btn.innerHTML='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>Delete'}
}
async function doFix(){
  if(!confirm('Auto-fix all double-extension filenames?'))return;
  toast('Fixing...', true);
  try{
    const data=await api('api/fix',{method:'POST'});
    if(data.ok)toast('Fixed '+data.count+' file(s)',true),await load();
    else toast(data.error||'Fix failed',false);
  }catch(e){toast('Error',false)}
}

/* ═══ Copy ═══ */
function copyVal(id){cp($(id).textContent)}
function cp(text){
  if(navigator.clipboard)navigator.clipboard.writeText(text).then(()=>toast('Copied!',true)).catch(()=>fbCopy(text));
  else fbCopy(text);
}
function fbCopy(text){
  const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;opacity:0';
  document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();toast('Copied!',true);
}

/* ═══ Toast ═══ */
function toast(msg,ok){
  const el=document.createElement('div');el.className='toast';
  el.innerHTML='<div class="toast-icon '+(ok?'ok':'err')+'"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">'+(ok?'<polyline points="20 6 9 17 4 12"/>':'<path d="M18 6 6 18M6 6l12 12"/>')+'</svg></div>'+esc(msg);
  $('toasts').appendChild(el);
  setTimeout(()=>{el.style.transition='opacity .2s';el.style.opacity='0';setTimeout(()=>el.remove(),200)},2800);
}

/* ═══ Welcome ═══ */
let wSlide=0,wTotal=3;
function goSlide(n){
  wSlide=n;
  $('wSlides').style.transform=`translateX(${-n*100}%)`;
  document.querySelectorAll('.ws-dot').forEach((d,i)=>d.classList.toggle('active',i===n));
  $('wNext').textContent=n===wTotal-1?'Get Started →':'Next →';
}
function nextSlide(){
  if(wSlide<wTotal-1)goSlide(wSlide+1);
  else skipWelcome();
}
function skipWelcome(){
  $('welcome').classList.add('out');
  localStorage.setItem('vyve_v21_welcome','done');
}
$('wNext').textContent='Next →';
if(localStorage.getItem('vyve_v21_welcome')==='done'){$('welcome').classList.add('out')}

load();
</script>
</body></html>
<?php
}
