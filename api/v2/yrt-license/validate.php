<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Include the database configuration file to establish a PDO connection
require_once '../../config/database.php';

// Check if the request method is POST
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Initialize variables to capture POST data
    $license_key = null;
    $account_id = null;

    // Check if 'license_key' and 'account_id' are set via form-data (x-www-form-urlencoded)
    if (isset($_POST['license_key']) && isset($_POST['account_id'])) {
        $license_key = $_POST['license_key'];
        $account_id = $_POST['account_id'];
    }
    
    // If 'license_key' and 'account_id' are not set via form-data, try JSON input
    if (empty($license_key) || empty($account_id)) {
        $data = json_decode(file_get_contents("php://input"), true);
        $license_key = $data['license_key'] ?? null;
        $account_id = $data['account_id'] ?? null;
    }

    // Check if 'license_key' and 'account_id' are still empty after both checks
    if (empty($license_key) || empty($account_id)) {
        http_response_code(400);
        echo json_encode(['message' => 'Bad Request: Missing required fields (license_key, account_id)']);
        exit;
    }

    // Prepare SQL statement to prevent SQL injection
    $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license_key WHERE license_key = :license_key AND account_id = :account_id AND license_status = 'active'");
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
} else {
    http_response_code(405);
    echo json_encode(['message' => 'Method Not Allowed']);
}
?>