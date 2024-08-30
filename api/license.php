<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Include the database configuration file to establish a PDO connection
require_once 'config/database.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get license_key and account_id from POST request
    $license_key = $_POST['license_key'];
    $account_id = $_POST['account_id'];

    // Prepare SQL statement to prevent SQL injection
    $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license WHERE license_key = :license_key AND account_id = :account_id AND status = 'active'");
    $stmt->bindParam(':license_key', $license_key);
    $stmt->bindParam(':account_id', $account_id);
    
    // Execute the statement
    $stmt->execute();
    
    // Check if any rows are returned
    if ($stmt->rowCount() > 0) {
        echo "valid";
    } else {
        echo "invalid";
    }
}
?>
