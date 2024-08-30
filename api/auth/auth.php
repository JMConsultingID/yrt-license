<?php
// auth/auth.php

require_once __DIR__ . '/../config/database.php';  

function authenticate() {
    global $pdo; 
    
    $headers = apache_request_headers();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(['message' => 'Unauthorized']);
        exit();
    }

    $authHeader = $headers['Authorization'];
    $apiKey = str_replace('Bearer ', '', $authHeader);

    $stmt = $pdo->prepare("SELECT * FROM yrt_api_keys WHERE api_key = :api_key");
    $stmt->bindParam(':api_key', $apiKey);
    $stmt->execute();
    $apiKeyData = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$apiKeyData) {
        http_response_code(401);
        echo json_encode(['message' => 'Unauthorized']);
        exit();
    }
}
?>
