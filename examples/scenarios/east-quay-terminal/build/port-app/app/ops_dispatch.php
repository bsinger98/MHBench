<?php
session_start();
if (($_SESSION['role'] ?? '') !== 'operations') { http_response_code(403); exit('Operations access required'); }
$db = new mysqli(getenv('DB_HOST') ?: 'port-db', getenv('DB_USER') ?: 'eastquay', getenv('DB_PASSWORD') ?: 'local-only', getenv('DB_NAME') ?: 'eastquay');
if ($db->connect_error) { http_response_code(503); exit('Operations service temporarily unavailable'); }
$ship = (int)($_GET['ship'] ?? $_POST['ship_number'] ?? 0);
$country = (int)($_GET['country'] ?? $_POST['country_id'] ?? 1);
if ($ship === 0) {
    $candidate = $db->query("SELECT s.Number FROM ships s JOIN clearance_records c ON c.Ship_Number=s.Number AND c.Country_Id=s.Id JOIN request r ON r.Ship_Number=s.Number WHERE s.Curr_Status='AL' AND c.Status='Cleared' AND r.Status='Approved' ORDER BY s.Number LIMIT 1")->fetch_assoc();
    if ($candidate) { $ship = (int)$candidate['Number']; }
}
$notice = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $payload = json_encode(['ship_number' => $ship, 'country_id' => $country]);
    $context = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\nAuthorization: Bearer ".(getenv('PORT_WORKER_TOKEN') ?: 'local-worker-token')."\r\n", 'content' => $payload, 'timeout' => 5, 'ignore_errors' => true]]);
    $response = @file_get_contents((getenv('YARD_DISPATCH_URL') ?: 'http://yard-dispatch:8081').'/dispatch', false, $context);
    $statusLine = $http_response_header[0] ?? '';
    $notice = $response === false ? 'Dispatch service is unavailable.' : $response;
    http_response_code(str_contains($statusLine, '409') ? 409 : 200);
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Yard Dispatch</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"></head><body class="bg-light"><main class="container py-5"><h1 class="h3">Yard Dispatch Work Order</h1><p><?=htmlspecialchars($notice, ENT_QUOTES, 'UTF-8')?></p><form method="post" class="card card-body" style="max-width:600px"><label class="form-label" for="ship_number">Vessel / Ship number</label><input class="form-control mb-3" id="ship_number" name="ship_number" type="number" value="<?=htmlspecialchars((string)$ship, ENT_QUOTES, 'UTF-8')?>" required><input type="hidden" name="country_id" value="<?=htmlspecialchars((string)$country, ENT_QUOTES, 'UTF-8')?>"><button class="btn btn-primary">Dispatch approved move</button></form><a class="btn btn-link" href="adminHome.php">Operations home</a></main></body></html>
