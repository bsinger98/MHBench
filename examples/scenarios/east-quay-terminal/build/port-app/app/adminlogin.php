<?php
session_start();
$db = new mysqli(getenv('DB_HOST') ?: 'port-db', getenv('DB_USER') ?: 'eastquay', getenv('DB_PASSWORD') ?: 'local-only', getenv('DB_NAME') ?: 'eastquay');
if ($db->connect_error) { http_response_code(503); exit('Operations service temporarily unavailable'); }
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $staffId = (int)($_POST['user_id'] ?? 0);
    $email = (string)($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');
    $stmt = $db->prepare('SELECT Staff_Id, Name, Password_Hash, Role FROM port_staff WHERE Staff_Id=? AND Email=?');
    $stmt->bind_param('is', $staffId, $email);
    $stmt->execute();
    $staff = $stmt->get_result()->fetch_assoc();
    if ($staff && password_verify($password, $staff['Password_Hash'])) {
        session_regenerate_id(true);
        $_SESSION['staff_id'] = (int)$staff['Staff_Id'];
        $_SESSION['name'] = $staff['Name'];
        $_SESSION['role'] = $staff['Role'];
        header('Location: adminHome.php');
        exit;
    }
    $error = 'Invalid credentials';
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Port Operations Sign In</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"></head>
<body class="bg-light"><main class="container py-5" style="max-width:560px"><h1 class="h3 mb-4">Port Operations</h1><?php if ($error): ?><div class="alert alert-danger"><?=htmlspecialchars($error, ENT_QUOTES, 'UTF-8')?></div><?php endif; ?><form method="post" class="card card-body"><label class="form-label" for="user_id">Staff ID</label><input class="form-control mb-3" id="user_id" name="user_id" type="number" required><label class="form-label" for="email">Work email</label><input class="form-control mb-3" id="email" name="email" type="email" required><label class="form-label" for="password">Password</label><input class="form-control mb-3" id="password" name="password" type="password" required><button class="btn btn-primary">Sign in</button></form></main></body></html>
