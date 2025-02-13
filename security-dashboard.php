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

// Function to run when plugin is activated
function security_dashboard_activate() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'security_logs';

    $charset_collate = $wpdb->get_charset_collate();

    // Create a table for security logs
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

// Function to log failed login attempts
function security_dashboard_log_failed_login($username) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'security_logs';
    $ip_address = $_SERVER['REMOTE_ADDR'];

    // Insert login failure into database
    $wpdb->insert($table_name, [
        'ip_address' => $ip_address,
        'username' => $username,
        'event_type' => 'failed_login'
    ]);
}

// Hook into WordPress login failures
add_action('wp_login_failed', 'security_dashboard_log_failed_login');

// Register REST API endpoint
function security_dashboard_register_api() {
    register_rest_route('security-dashboard/v1', '/logs', array(
        'methods'  => 'GET',
        'callback' => 'security_dashboard_get_logs',
        'permission_callback' => '__return_true' // Temporary public access (we'll secure later)
    ));
}
add_action('rest_api_init', 'security_dashboard_register_api');

// Function to fetch logs from the database
function security_dashboard_get_logs() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'security_logs';

    // Fetch last 10 failed login attempts
    $results = $wpdb->get_results("SELECT * FROM $table_name ORDER BY event_time DESC LIMIT 10");

    return rest_ensure_response($results); // Ensures proper JSON response
}





