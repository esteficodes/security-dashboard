<?php
/**
 * Plugin Name: Security Dashboard
 * Plugin URI:  https://yourwebsite.com
 * Description: A simple security plugin that logs failed login attempts.
 * Version: 1.0
 * Author: Your Name
 */

if (!defined('ABSPATH')) {
    exit; // Prevent direct access
}

// ✅ 1. Start session for authentication (Only One Instance)
function security_dashboard_enable_authentication() {
    if (!session_id()) {
        session_start();
    }

    if (isset($_COOKIE['wordpress_logged_in_' . COOKIEHASH])) {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Basic ' . base64_encode($_COOKIE['wordpress_logged_in_' . COOKIEHASH]);
    }
}
add_action('init', 'security_dashboard_enable_authentication');


function security_dashboard_allow_cors() {
    if (isset($_SERVER['HTTP_ORIGIN'])) {
        header("Access-Control-Allow-Origin: http://localhost:5173"); // ✅ Allow React frontend
        header("Access-Control-Allow-Credentials: true"); // ✅ Allow authentication cookies
        header("Access-Control-Allow-Methods: GET, OPTIONS");
        header("Access-Control-Allow-Headers: Authorization, Content-Type, X-WP-Nonce");
    }
}
add_action('rest_api_init', 'security_dashboard_allow_cors');


// ✅ 3. Create Security Logs Table on Plugin Activation
function security_dashboard_activate() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'security_logs';

    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        ip_address VARCHAR(100) NOT NULL,
        username VARCHAR(100) NOT NULL,
        event_type VARCHAR(50) NOT NULL,
        event_time DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
        PRIMARY KEY (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}
register_activation_hook(__FILE__, 'security_dashboard_activate');

// ✅ 4. Log Failed Login Attempts
function security_dashboard_log_failed_login($username) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'security_logs';
    $ip_address = $_SERVER['REMOTE_ADDR'];

    $wpdb->insert($table_name, [
        'ip_address' => $ip_address,
        'username' => $username,
        'event_type' => 'failed_login'
    ]);
}
add_action('wp_login_failed', 'security_dashboard_log_failed_login');

// ✅ Register REST API Route
function security_dashboard_register_api() {
    register_rest_route('security-dashboard/v1', '/logs', array(
        'methods'  => 'GET',
        'callback' => function() {
            if (!is_user_logged_in()) {
                return new WP_Error('rest_forbidden', __('You must be logged in to access this.'), array('status' => 403));
            }

            if (!current_user_can('manage_options')) {
                return new WP_Error('rest_forbidden', __('Only administrators can view security logs.'), array('status' => 403));
            }

            return security_dashboard_get_logs();
        },
        'permission_callback' => function() {
            return current_user_can('manage_options'); // ✅ Ensures only admins pass
        }
    ));
}
add_action('rest_api_init', 'security_dashboard_register_api');

// ✅ 6. Fetch Logs from Database
function security_dashboard_get_logs() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'security_logs';

    // Fetch last 10 failed login attempts
    $results = $wpdb->get_results("SELECT * FROM $table_name ORDER BY event_time DESC LIMIT 10");

    return rest_ensure_response($results); // Ensures proper JSON response
}

