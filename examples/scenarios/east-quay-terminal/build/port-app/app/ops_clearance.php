<?php
session_start();
if (($_SESSION['role'] ?? '') !== 'operations') { http_response_code(403); exit('Operations access required'); }
$db = new mysqli(getenv('DB_HOST') ?: 'port-db', getenv('DB_USER') ?: 'eastquay', getenv('DB_PASSWORD') ?: 'local-only', getenv('DB_NAME') ?: 'eastquay');
if ($db->connect_error) { http_response_code(503); exit('Operations service temporarily unavailable'); }
$notice = '';
$ship = (int)($_GET['ship'] ?? $_POST['ship_number'] ?? 0);
$country = (int)($_GET['country'] ?? $_POST['country_id'] ?? 1);
if ($ship === 0) {
    $candidate = $db->query("SELECT Ship_Number, Country_Id FROM clearance_records WHERE Status='On Hold' ORDER BY Ship_Number LIMIT 1")->fetch_assoc();
    if ($candidate) {
        $ship = (int)$candidate['Ship_Number'];
        $country = (int)$candidate['Country_Id'];
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $db->prepare("UPDATE clearance_records SET Status='Cleared', Updated_By=? WHERE Ship_Number=? AND Country_Id=?");
    $who = (string)($_SESSION['name'] ?? 'Operations');
    $stmt->bind_param('sii', $who, $ship, $country);
    $stmt->execute();
    if ($stmt->affected_rows >= 0) {
        $stmt = $db->prepare("UPDATE request SET Status='Approved' WHERE Ship_Number=?");
        $stmt->bind_param('i', $ship);
        $stmt->execute();
        $notice = 'Clearance decision recorded.';
    }
}
$stmt = $db->prepare('SELECT s.Name, s.Curr_Status, r.Status AS Request_Status, c.Status AS Clearance_Status, c.Hold_Reason FROM ships s JOIN clearance_records c ON c.Ship_Number=s.Number AND c.Country_Id=s.Id LEFT JOIN request r ON r.Ship_Number=s.Number WHERE s.Number=? AND s.Id=?');
$stmt->bind_param('ii', $ship, $country);
$stmt->execute();
$record = $stmt->get_result()->fetch_assoc();
function e($value) { return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Clearance Review</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"></head><body class="bg-light"><main class="container py-5"><h1 class="h3">Shipment Clearance Review</h1><p><?=e($notice)?></p><?php if ($record): ?><div class="card card-body mb-3"><div>Vessel: <?=e($record['Name'])?></div><div>Request: <?=e($record['Request_Status'])?></div><div>Clearance: <?=e($record['Clearance_Status'])?></div><div>Reason: <?=e($record['Hold_Reason'])?></div></div><form method="post"><input type="hidden" name="ship_number" value="<?=e($ship)?>"><input type="hidden" name="country_id" value="<?=e($country)?>"><button class="btn btn-primary">Record clearance decision</button></form><a class="btn btn-link" href="ops_dispatch.php?ship=<?=e($ship)?>&country=<?=e($country)?>">Open yard dispatch</a><?php else: ?><p>No shipment record was found.</p><?php endif; ?><a class="btn btn-link" href="adminHome.php">Operations home</a></main></body></html>
