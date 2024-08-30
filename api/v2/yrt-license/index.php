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

// Remove the base path from the request URI to extract the action or ID
$action = str_replace($base_path, '', parse_url($request_uri, PHP_URL_PATH)); // Only parse path, not query string
$action = trim($action, '/'); // Remove any leading or trailing slashes

switch ($method) {
    case 'GET':
        if (is_numeric($action)) {
            // If action is a numeric ID, fetch the specific license by ID
            handleGetRequestById($pdo, intval($action));
        } elseif (empty($action)) {
            // Default action: Fetch all licenses with pagination and search
            handleGetRequest($pdo);
        } else {
            http_response_code(400);
            echo json_encode(['message' => 'Bad Request: Invalid action']);
        }
        break;
    case 'POST':
        if ($action === 'validate') {
            validateLicense($pdo);
        } elseif ($action === 'new') {
            handleNewPostRequest($pdo);
        } else {
            handlePostRequest($pdo);
        }
        break;
    case 'PUT':
    case 'PATCH':
        if ($action === 'edit') {
            handleEditRequest($pdo);
        } else {
            http_response_code(400);
            echo json_encode(['message' => 'Bad Request: Unknown action for edit']);
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
        $base_query .= "(email LIKE :search OR full_name LIKE :search OR license_key LIKE :search OR order_id LIKE :search)";
        $count_query .= $account_id ? " AND " : " WHERE ";
        $count_query .= "(email LIKE :search OR full_name LIKE :search OR license_key LIKE :search OR order_id LIKE :search)";
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

// Function to handle fetching a specific license by ID
function handleGetRequestById($pdo, $id) {
    // Prepare the SQL query to fetch data for a specific license ID
    $stmt = $pdo->prepare("SELECT * FROM yrt_ea_license_key WHERE id = :id");
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    $license = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($license) {
        // If license is found, return it as JSON
        echo json_encode($license);
    } else {
        // If no license is found, return a 404 error
        http_response_code(404);
        echo json_encode(['message' => 'License not found']);
    }
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
    $account_modify_date = date('Y-m-d H:i:s');

    // Insert new license data into the database
    $stmt = $pdo->prepare("INSERT INTO yrt_ea_license_key (email, full_name, order_id, product_id, product_name, account_id, license_key, license_expiration, license_status, source, additional_info, account_creation_date, account_modify_date) 
                           VALUES (:email, :full_name, :order_id, :product_id, :product_name, :account_id, :license_key, :license_expiration, :license_status, :source, :additional_info, :account_creation_date, :account_modify_date)");
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
    $stmt->bindParam(':account_modify_date', $account_modify_date); 
    
    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(['message' => 'License inserted successfully to the database']);
    } else {
        http_response_code(500);
        echo json_encode(['message' => 'Internal Server Error']);
    }
}

// Function to handle editing a license
function handleEditRequest($pdo) {
    // Parse the input data as JSON
    $data = json_decode(file_get_contents("php://input"), true);

    // Validate input data
    if (!isset($data['id'])) {
        http_response_code(400);
        echo json_encode(['message' => 'Bad Request: Missing required field (id)']);
        return;
    }

    // Set up variables
    $id = $data['id'];
    $email = isset($data['email']) ? $data['email'] : null;
    $full_name = isset($data['full_name']) ? $data['full_name'] : null;
    $account_id = isset($data['account_id']) ? $data['account_id'] : null;
    $license_key = isset($data['license_key']) ? $data['license_key'] : null;
    $license_status = isset($data['license_status']) ? $data['license_status'] : null;
    $additional_info = isset($data['additional_info']) ? $data['additional_info'] : null;
    $account_modify_date = date('Y-m-d H:i:s');

    // Prepare the SQL query to update the license
    $fields = [];
    if ($email !== null) $fields[] = "email = :email";
    if ($full_name !== null) $fields[] = "full_name = :full_name";
    if ($account_id !== null) $fields[] = "account_id = :account_id";
    if ($license_key !== null) $fields[] = "license_key = :license_key";
    if ($license_status !== null) $fields[] = "license_status = :license_status";
    if ($additional_info !== null) $fields[] = "additional_info = :additional_info";
    if ($account_modify_date !== null) $fields[] = "account_modify_date = :account_modify_date";

    if (empty($fields)) {
        http_response_code(400);
        echo json_encode(['message' => 'Bad Request: No fields to update']);
        return;
    }

    $sql = "UPDATE yrt_ea_license_key SET " . implode(", ", $fields) . " WHERE id = :id";
    $stmt = $pdo->prepare($sql);

    // Bind parameters
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    if ($email !== null) $stmt->bindParam(':email', $email, PDO::PARAM_STR);
    if ($full_name !== null) $stmt->bindParam(':full_name', $full_name, PDO::PARAM_STR);
    if ($account_id !== null) $stmt->bindParam(':account_id', $account_id, PDO::PARAM_STR);
    if ($license_key !== null) $stmt->bindParam(':license_key', $license_key, PDO::PARAM_STR);
    if ($license_status !== null) $stmt->bindParam(':license_status', $license_status, PDO::PARAM_STR);
    if ($additional_info !== null) $stmt->bindParam(':additional_info', $additional_info, PDO::PARAM_STR);
    if ($account_modify_date !== null) $stmt->bindParam(':account_modify_date', $account_modify_date, PDO::PARAM_STR);

    // Execute the query
    if ($stmt->execute()) {
        http_response_code(200);
        echo json_encode(['message' => 'License updated successfully']);
    } else {
        http_response_code(500);
        echo json_encode(['message' => 'Internal Server Error: Unable to update license']);
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