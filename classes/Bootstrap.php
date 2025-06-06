<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

namespace Jcore\Security;

use Jcore\Ydin\BootstrapInterface;

if ( is_file( __DIR__ . '/../vendor/autoload.php' ) ) {
	require_once __DIR__ . '/../vendor/autoload.php';
}

/**
 * The bootstrap class, should be used by all dependencies.
 */
class Bootstrap implements BootstrapInterface {
	/**
	 * The singleton instance.
	 *
	 * @var Bootstrap|null
	 */
	private static ?Bootstrap $instance = null;

	/**
	 * Bootstrap constructor.
	 */
	private function __construct() {
		ContentSecurityPolicy::init();
		self::add_menu_page();
	}

	/**
	 * Get the singleton instance.
	 *
	 * Returns the single instance of the Bootstrap class, creating it if it does not already exist.
	 *
	 * @return Bootstrap The singleton instance of the Bootstrap class.
	 */
	public static function init(): Bootstrap {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Adds the Security settings submenu page to the WordPress admin,
	 * under the 'Settings' menu, if the ACF plugin function exists .
	 *
	 * This uses the Advanced Custom Fields( ACF ) function * acf_add_options_sub_page to register a new options sub page()
	 * for managing security - related settings .
	 *
	 * The submenu will appear as 'Security' under 'Settings' and
	 * will be accessible to users with the 'manage_options' capability .
	 */
	public static function add_menu_page(): void {
		if ( function_exists( 'acf_add_options_sub_page' ) ) {
			acf_add_options_sub_page(
				array(
					'page_title'  => __( 'Security Settings' ),
					'menu_title'  => __( 'Security' ),
					'menu_slug'   => 'security',
					'capability'  => 'manage_options',
					'parent_slug' => 'options-general.php',
				)
			);
		}
	}
}
