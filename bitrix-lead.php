<?php
/**
 * Прием заявок с сайта buildhousespb.ru и отправка письма на почту.
 *
 * Все происходит на этом сервере (reg.ru, Россия): скрипт принимает данные
 * формы и сам отправляет письмо через встроенную функцию PHP - никакой
 * сторонний сервис (Web3Forms, Bitrix24, Gmail и т.п.) не участвует,
 * и никакой секретный ключ наружу, в код страницы, не передается.
 * Почта получателя - на inbox.ru (VK/Mail.ru Group, инфраструктура в РФ),
 * поэтому персональные данные посетителей не покидают территорию России.
 *
 * Разместить этот файл в корне хостинга reg.ru рядом с index.html,
 * так чтобы он открывался по адресу https://buildhousespb.ru/bitrix-lead.php
 */

header('Content-Type: application/json; charset=utf-8');

// --- CORS: разрешаем запросы только со своего домена ---
$allowedOrigins = [
    'https://buildhousespb.ru',
    'https://www.buildhousespb.ru',
];
$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
if (in_array($origin, $allowedOrigins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// ─────────────────────────────────────────────────────────────
// Куда падают заявки
// ─────────────────────────────────────────────────────────────
$LEAD_TO = 'buildhousespb@inbox.ru';

// Секретный ключ Cloudflare Turnstile - для серверной проверки капчи.
// Хранится только здесь, в браузере посетителя его нет.
$TURNSTILE_SECRET = '0x4AAAAADurHB8dyjuTGuFPvOQ8s6BVf9s';

// --- Читаем данные формы ---
$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Bad request']);
    exit;
}

/**
 * Убирает переносы строк из значения, чтобы его нельзя было использовать
 * для инъекции лишних заголовков письма (классическая уязвимость PHP mail()).
 */
function clean_field($value) {
    $value = (string)$value;
    $value = str_replace(["\r", "\n", "\0"], '', $value);
    return trim($value);
}

$name      = clean_field($data['name']    ?? '');
$phone     = clean_field($data['phone']   ?? '');
$email     = clean_field($data['email']   ?? '');
$message   = clean_field($data['message'] ?? '');
$tsToken   = clean_field($data['turnstileToken'] ?? '');
$honeypot  = clean_field($data['website'] ?? '');

// ─────────────────────────────────────────────────────────────
// Honeypot: это скрытое от людей поле, но простые боты, заполняющие
// все input на странице, попадаются на нем. Если оно не пустое - это бот.
// Отвечаем притворным success (чтобы не выдавать боту, что его вычислили),
// но письмо не отправляем.
// ─────────────────────────────────────────────────────────────
if ($honeypot !== '') {
    echo json_encode(['success' => true]);
    exit;
}

if ($phone === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Phone required']);
    exit;
}

if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $email = ''; // отбрасываем некорректный email, но не блокируем заявку
}

// ─────────────────────────────────────────────────────────────
// Проверка Cloudflare Turnstile на сервере
// ─────────────────────────────────────────────────────────────
function verify_turnstile($token, $secret, $remoteIp) {
    if ($token === '' || $secret === '') {
        return true; // капча не настроена/не пришла - не блокируем заявку
    }
    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $secret,
            'response' => $token,
            'remoteip' => $remoteIp,
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 8,
    ]);
    $resp = curl_exec($ch);
    curl_close($ch);
    if ($resp === false) {
        // Сеть до Cloudflare недоступна - не теряем настоящую заявку из-за этого
        return true;
    }
    $json = json_decode($resp, true);
    return !empty($json['success']);
}

$remoteIp = $_SERVER['REMOTE_ADDR'] ?? '';
if (!verify_turnstile($tsToken, $TURNSTILE_SECRET, $remoteIp)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Captcha verification failed']);
    exit;
}

// ─────────────────────────────────────────────────────────────
// Формируем и отправляем письмо
// ─────────────────────────────────────────────────────────────
$subjectText = 'Заявка с сайта BuildHouse';
$subject = '=?UTF-8?B?' . base64_encode($subjectText) . '?=';

$bodyLines = [
    'Имя: '      . ($name !== '' ? $name : '-'),
    'Телефон: '  . $phone,
    'Email: '    . ($email !== '' ? $email : '-'),
    'Сообщение: ' . ($message !== '' ? $message : '-'),
    '',
    'Источник: buildhousespb.ru',
];
$body = implode("\r\n", $bodyLines);

$fromAddr = 'noreply@buildhousespb.ru';
$headers = [];
$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-Type: text/plain; charset=UTF-8';
$headers[] = 'From: BuildHouse Site <' . $fromAddr . '>';
if ($email !== '') {
    $headers[] = 'Reply-To: ' . $email;
}
$headersStr = implode("\r\n", $headers);

$sent = @mail($LEAD_TO, $subject, $body, $headersStr);

if ($sent) {
    echo json_encode(['success' => true]);
} else {
    http_response_code(502);
    echo json_encode(['success' => false, 'error' => 'Mail sending failed']);
}
