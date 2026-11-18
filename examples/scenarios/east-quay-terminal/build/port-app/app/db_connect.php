<!DOCTYPE html>
<html>
<head>
    <title></title>
</head>
<body>

<a href="index.php">Home</a>
<br>
<br>

<?php

$mysql_host = getenv("DB_HOST") ?: "db";
$mysql_database = getenv("DB_NAME") ?: "eastquay";
$mysql_user = getenv("DB_USER") ?: "eastquay";
$mysql_password = getenv("DB_PASSWORD") ?: "local-only";
# MySQL with PDO_MYSQL  
$db = new PDO("mysql:host=$mysql_host;dbname=$mysql_database", $mysql_user, $mysql_password);

$query = file_get_contents("Create_Tables.sql");

$stmt = $db->prepare($query);

if ($stmt->execute()){
     echo "Success";
}else{ 
     echo "Fail";
}

?>
