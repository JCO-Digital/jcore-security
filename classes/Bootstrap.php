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
	 * @return Bootstrap
	 */
	public static function init(): Bootstrap {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Add the settings page.
	 *
	 * @return void
	 */
	public static function add_menu_page(): void {
		$child = acf_add_options_sub_page(
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
