<?php
// api/v1/yrt-license/index.php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
header("Content-Type: application/json");

// Import authentication and database configuration files
require_once '../../auth/auth.php';
require_once '../../config/database.php';

// Check authentication
authenticate();

// Get the request URI and method
$request_uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

// Define the base path for the API
$base_path = '/api/v1/yrt-license/';

// Remove the base path from the request URI to extract the action
$action = str_replace($base_path, '', $request_uri);
$action = trim($action, '/'); // Remove any leading or trailing slashes

switch ($method) {
    case 'GET':
        handleGetRequest($pdo, $action); // Ensure both arguments are passed
        break;
    case 'POST':
        if ($action === 'validate') {
            validateLicense($pdo);
        } else {
            handlePostRequest($pdo);
        }
        break;
    default:
        http_response_code(405);
        echo json_encode(['message' => 'Method Not Allowed']);
        break;
}

function handleGetRequest($pdo, $account_id) {
    if ($account_id) {
        // Prepare the SQL query to fetch data for a specific account_id
        $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license WHERE account_id = :account_id");
        $stmt->bindParam(':account_id', $account_id);
        $stmt->execute();
        $licenses = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($licenses) {
            echo json_encode($licenses);
        } else {
            http_response_code(404);
            echo json_encode(['message' => 'No data found for the provided account_id']);
        }
    } else {
        // Retrieve all license data if account_id is not provided
        $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license");
        $stmt->execute();
        $licenses = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode($licenses);
    }
}

function handlePostRequest($pdo) {
    // Get JSON data from the request body
    $data = json_decode(file_get_contents("php://input"), true);

    // Check if the 'license_key' and 'account_id' parameters exist
    if (!isset($data['license_key']) || !isset($data['account_id'])) {
        http_response_code(400);
        echo json_encode(['message' => 'Bad Request: Missing required fields (license_key, account_id)']);
        return;
    }

    $license_key = $data['license_key'];
    $account_id = $data['account_id'];

    // Check if 'license_key' and 'account_id' have values
    if (empty($license_key) || empty($account_id)) {
        http_response_code(400);
        echo json_encode(['message' => 'Bad Request: Fields license_key and account_id cannot be empty']);
        return;
    }

    // Validate the format of license_key (length and pattern)
    if (!preg_match('/^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/', $license_key)) {
        http_response_code(400);
        echo json_encode(['message' => 'Bad Request: Invalid license_key format. It must be 16 characters long with dashes (e.g., XXXX-XXXX-XXXX-XXXX)']);
        return;
    }

    // Check if the license_key and account_id already exist in the database
    $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license WHERE license_key = :license_key AND account_id = :account_id");
    $stmt->bindParam(':license_key', $license_key);
    $stmt->bindParam(':account_id', $account_id);
    $stmt->execute();
    $existingLicense = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingLicense) {
        http_response_code(409); // 409 Conflict
        echo json_encode(['message' => 'Conflict: The combination of license_key and account_id already exists']);
        return;
    }

    $status = 'active'; // Set status as active
    $activation_date = date('Y-m-d H:i:s'); // Set current time as activation date

    // Insert new license data into the database
    $stmt = $pdo->prepare("INSERT INTO yrt_ea_license (license_key, account_id, status, activation_date) VALUES (:license_key, :account_id, :status, :activation_date)");
    $stmt->bindParam(':license_key', $license_key);
    $stmt->bindParam(':account_id', $account_id);
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':activation_date', $activation_date);

    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(['message' => 'License Inserted successfully to database']);
    } else {
        http_response_code(500);
        echo json_encode(['message' => 'Internal Server Error']);
    }
}

function validateLicense($pdo) {
 // Check if the request method is POST
 if ($_SERVER["REQUEST_METHOD"] == "POST") {
     // Handle both JSON and form-urlencoded
     $data = json_decode(file_get_contents("php://input"), true);

     if (!$data) { // If JSON decode fails, try form-urlencoded
         $data = $_POST;
     }
     
     // Check if the 'license_key' and 'account_id' parameters exist
     if (!isset($data['license_key']) || !isset($data['account_id'])) {
         http_response_code(400);
         echo json_encode(['message' => 'Bad Request: Missing required fields (license_key, account_id)']);
         return;
     }

     $license_key = $data['license_key'];
     $account_id = $data['account_id'];

     // Prepare SQL statement to prevent SQL injection
     $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license WHERE license_key = :license_key AND account_id = :account_id AND status = 'active'");
     $stmt->bindParam(':license_key', $license_key);
     $stmt->bindParam(':account_id', $account_id);
     
     // Execute the statement
     $stmt->execute();
     
     // Check if any rows are returned
     if ($stmt->rowCount() > 0) {
         http_response_code(200);
         echo json_encode(['message' => 'valid']);
     } else {
         http_response_code(404);
         echo json_encode(['message' => 'invalid']);
     }
 } else {
     http_response_code(405);
     echo json_encode(['message' => 'Method Not Allowed']);
 }
}
?>