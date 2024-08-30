<?php
// api/v2/yrt-license/index.php

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
$base_path = '/api/v2/yrt-license/';

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
        } elseif ($action === 'new'){
            handleNewPostRequest($pdo);
        } else {
            handlePostRequest($pdo);
        }
        break;
    default:
        http_response_code(405);
        echo json_encode(['message' => 'Method Not Allowed']);
        break;
}

function handleGetRequest($pdo, $account_id = null) {
    // Get query parameters for pagination and search
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $search = isset($_GET['search']) ? trim($_GET['search']) : '';

    // Set up pagination
    $offset = ($page - 1) * $limit;

    // Base SQL query
    $base_query = "SELECT * FROM yrt_ea_license_key";
    $count_query = "SELECT COUNT(*) FROM yrt_ea_license_key";

    // Modify query for account_id
    if ($account_id) {
        $base_query .= " WHERE account_id = :account_id";
        $count_query .= " WHERE account_id = :account_id";
    }

    // Modify query for search
    if ($search) {
        $search_term = '%' . $search . '%';
        $base_query .= $account_id ? " AND " : " WHERE ";
        $base_query .= "(email LIKE :search OR full_name LIKE :search OR license_key LIKE :search)";
        $count_query .= $account_id ? " AND " : " WHERE ";
        $count_query .= "(email LIKE :search OR full_name LIKE :search OR license_key LIKE :search)";
    }

    // Add LIMIT and OFFSET for pagination
    $base_query .= " LIMIT :limit OFFSET :offset";

    // Prepare the SQL statement for fetching data
    $stmt = $pdo->prepare($base_query);

    // Bind parameters if needed
    if ($account_id) {
        $stmt->bindParam(':account_id', $account_id, PDO::PARAM_STR);
    }
    if ($search) {
        $stmt->bindParam(':search', $search_term, PDO::PARAM_STR);
    }
    $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);

    $stmt->execute();
    $licenses = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Prepare the SQL statement for counting total results
    $count_stmt = $pdo->prepare($count_query);

    // Bind parameters if needed
    if ($account_id) {
        $count_stmt->bindParam(':account_id', $account_id, PDO::PARAM_STR);
    }
    if ($search) {
        $count_stmt->bindParam(':search', $search_term, PDO::PARAM_STR);
    }

    $count_stmt->execute();
    $total_results = $count_stmt->fetchColumn();

    // Calculate total pages
    $total_pages = ceil($total_results / $limit);

    // Return the response
    echo json_encode([
        'data' => $licenses,
        'total' => $total_results,
        'page' => $page,
        'total_pages' => $total_pages,
    ]);
}


function handlePostRequest($pdo) {
    // Get JSON data from the request body
    $data = json_decode(file_get_contents("php://input"), true);

    // Check if required parameters exist
    $required_fields = ['email', 'full_name', 'order_id', 'product_id', 'product_name', 'account_id', 'license_key', 'license_expiration','source'];
    foreach ($required_fields as $field) {
        if (!isset($data[$field]) || empty($data[$field])) {
            http_response_code(400);
            echo json_encode(['message' => 'Bad Request: Missing or empty required field (' . $field . ')']);
            return;
        }
    }

    $email = $data['email'];
    $full_name = $data['full_name'];
    $order_id = $data['order_id'];
    $product_id = $data['product_id'];
    $product_name = $data['product_name'];
    $account_id = $data['account_id'];
    $license_key = $data['license_key'];
    $license_expiration = $data['license_expiration'];
    $source = $data['source'];
    $additional_info = isset($data['additional_info']) ? $data['additional_info'] : ''; // Optional field

    // Validate the format of license_key (length and pattern)
    if (!preg_match('/^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/', $license_key)) {
        http_response_code(400);
        echo json_encode(['message' => 'Bad Request: Invalid license_key format. It must be 16 characters long with dashes (e.g., XXXX-XXXX-XXXX-XXXX)']);
        return;
    }

    // Check if the license_key and account_id already exist in the database
    $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license_key WHERE license_key = :license_key AND account_id = :account_id");
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
    $stmt = $pdo->prepare("INSERT INTO yrt_ea_license_key (email, full_name, order_id, product_id, product_name, account_id, license_key, license_expiration, license_status, source, additional_info, account_creation_date) 
                           VALUES (:email, :full_name, :order_id, :product_id, :product_name, :account_id, :license_key, :license_expiration, :license_status, :source, :additional_info, :account_creation_date)");
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':full_name', $full_name);
    $stmt->bindParam(':order_id', $order_id);
    $stmt->bindParam(':product_id', $product_id);
    $stmt->bindParam(':product_name', $product_name);
    $stmt->bindParam(':account_id', $account_id);
    $stmt->bindParam(':license_key', $license_key);
    $stmt->bindParam(':license_expiration', $license_expiration);
    $stmt->bindParam(':license_status', $status);
    $stmt->bindParam(':source', $source);
    $stmt->bindParam(':additional_info', $additional_info);
    $stmt->bindParam(':account_creation_date', $activation_date); 
    
    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(['message' => 'License inserted successfully to the database']);
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
     $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license_key WHERE license_key = :license_key AND account_id = :account_id AND license_status = 'active'");
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