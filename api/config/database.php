<?php
// config/database.php

$host = 'localhost';
$dbname = 'u613137698_4p1_yRt_L1c3ns';
$username = 'u613137698_4p1_yRt_L1c3ns';
$password = 'SbaF@>D3k';
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Could not connect to the database $dbname :" . $e->getMessage());
}
?>