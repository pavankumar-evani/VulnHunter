<?php
/*
 * vuln-app.php - a deliberately vulnerable demo PHP app used ONLY to test
 * VulnHunter's multi-language scanner coverage. DO NOT deploy this anywhere. It
 * contains intentional security flaws for demonstration purposes only.
 *
 * Planted vulnerabilities (for scoring / demo reference):
 *   1. SQL Injection via mysqli_query string concat   -> CWE-89
 *   2. Local File Inclusion via include($_GET[...])    -> CWE-98
 *   3. unserialize() on untrusted input                -> CWE-502
 */

$conn = mysqli_connect("localhost", "vulnshop_admin", "SuperSecretP@ss123", "vulnshop");

// VULN 1: SQL Injection (CWE-89) - user id is concatenated directly into the query
// string instead of using a prepared statement with bound parameters.
function get_user($conn, $user_id) {
    $query = "SELECT id, username, email FROM users WHERE id = " . $user_id;
    $result = mysqli_query($conn, $query);
    return mysqli_fetch_assoc($result);
}

// VULN 2: Local File Inclusion (CWE-98) - the "page" query param is passed straight
// into include() with no allow-list or path sanitization, letting an attacker traverse
// to or execute arbitrary files on the server.
function render_page() {
    $page = $_GET['page'];
    include($page . '.php');
}

// VULN 3: PHP Object Injection via unserialize() (CWE-502) - untrusted cookie data is
// unserialized directly, allowing an attacker to instantiate arbitrary object graphs
// and trigger magic methods (__wakeup/__destruct) as a gadget chain.
function load_session_data() {
    $raw = $_COOKIE['session_data'];
    $session = unserialize($raw);
    return $session;
}

if (isset($_GET['id'])) {
    $user = get_user($conn, $_GET['id']);
    echo json_encode($user);
}

if (isset($_GET['page'])) {
    render_page();
}

if (isset($_COOKIE['session_data'])) {
    $session = load_session_data();
}
