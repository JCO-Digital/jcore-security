<?php

namespace Jcore\Security;

use Jcore\Ydin\Settings\Option;

class ContentSecurityPolicy extends Option {
	/**
	 * Array that contains the "saved" settings.
	 *
	 * @var array
	 */
	protected static array $data = array();

	/**
	 * Array that contains all the fields.
	 *
	 * @var array
	 */
	protected static array $fields = array();

	/**
	 * Array that contains all the policies.
	 *
	 * @var array
	 */
	protected static array $policies = array(
		'default'  => array(
			'enabled'    => true,
			'self'       => false,
			'inline'     => false,
			'eval'       => false,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
		'connect'  => array(
			'enabled'    => false,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
		'font'     => array(
			'enabled'    => true,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => true,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => 'https://fonts.gstatic.com',
		),
		'frame'    => array(
			'enabled'    => true,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
		'img'      => array(
			'enabled'    => true,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => true,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => 'https://secure.gravatar.com',
		),
		'manifest' => array(
			'enabled'    => false,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
		'media'    => array(
			'enabled'    => false,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
		'prefetch' => array(
			'enabled'    => false,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
		'script'   => array(
			'enabled'    => true,
			'self'       => true,
			'inline'     => true,
			'eval'       => true,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
		'style'    => array(
			'enabled'    => true,
			'self'       => true,
			'inline'     => true,
			'eval'       => true,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => 'https://fonts.googleapis.com',
		),
		'worker'   => array(
			'enabled'    => false,
			'self'       => true,
			'inline'     => false,
			'eval'       => false,
			'data'       => false,
			'wss'        => false,
			'all_https'  => false,
			'allow_urls' => '',
		),
	);

	/**
	 * Array that contains all the non-experimental permissions.
	 *
	 * @var array
	 */
	protected static array $permissions = array(
		'camera'          => array(
			'enabled'    => true,
			'self'       => false,
			'allow_none' => true,
			'allow_all'  => false,
			'allow_urls' => '',
		),
		'display-capture' => array(
			'enabled'    => true,
			'self'       => true,
			'allow_none' => false,
			'allow_all'  => false,
			'allow_urls' => '',
		),
		'fullscreen'      => array(
			'enabled'    => false,
			'self'       => true,
			'allow_none' => false,
			'allow_all'  => false,
			'allow_urls' => '',
		),
		'geolocation'     => array(
			'enabled'    => true,
			'self'       => true,
			'allow_none' => false,
			'allow_all'  => false,
			'allow_urls' => '',
		),
		'microphone'      => array(
			'enabled'    => true,
			'self'       => false,
			'allow_none' => true,
			'allow_all'  => false,
			'allow_urls' => '',
		),
		'web-share'       => array(
			'enabled'    => false,
			'self'       => true,
			'allow_none' => false,
			'allow_all'  => false,
			'allow_urls' => '',
		),
	);


	const POLICY_OPTION_NAME = 'jcore_security_csp_data';

	/**
	 * Initialize everything.
	 *
	 * @return void
	 */
	public static function init(): void {
		parent::init();
		static::create_acf();
		add_action( 'send_headers', '\Jcore\Security\ContentSecurityPolicy::send_headers' );
		add_action( 'acf/save_post', '\Jcore\Security\ContentSecurityPolicy::save_settings' );
	}

	/**
	 * Return the setting definition array.
	 *
	 * @return array
	 */
	protected static function get_fields(): array {
		return apply_filters(
			'jcore_init_security_fields',
			array(
				'security'    => array(
					'title'       => __( 'Security' ),
					'description' => __( 'Security Settings', 'jcore' ),
					'fields'      => array(
						'hsts_enable'       => array(
							'type'    => 'true_false',
							'label'   => 'HSTS',
							'default' => true,
							'width'   => '15',
						),
						'nosniff_enable'    => array(
							'type'    => 'true_false',
							'label'   => 'No-Sniff',
							'default' => true,
							'width'   => '15',
						),
						'xss_enable'        => array(
							'type'    => 'true_false',
							'label'   => 'XSS protection',
							'default' => true,
							'width'   => '15',
						),
						'referrer_enable'   => array(
							'type'    => 'true_false',
							'label'   => 'Referrer Policy',
							'default' => true,
							'width'   => '15',
						),
						'csp_enable'        => array(
							'type'    => 'true_false',
							'label'   => 'Enable CSP',
							'default' => true,
							'width'   => '15',
						),
						'csp_test_mode'     => array(
							'type'    => 'true_false',
							'label'   => 'CSP Test Mode',
							'default' => false,
							'width'   => '15',
						),
						'always_allow_urls' => array(
							'type'    => 'text',
							'label'   => 'Always Allow Urls',
							'default' => '',
						),
					),
				),
				'permissions' => array(
					'fields' => array(
						'permissions_enable' => array(
							'type'    => 'true_false',
							'label'   => 'Enable Permissions Policy',
							'default' => true,
							'width'   => '30',
						),
					),
				),
			)
		);
	}

	/**
	 * Get value from ACF field if it has been set otherwise use default.
	 *
	 * @param string $field_name The field to get.
	 * @param mixed  $default The value to default to if data has not been saved to field.
	 *
	 * @return mixed
	 */
	protected static function get_value( string $field_name, mixed $default ): mixed {
		return function_exists( 'get_field' ) ? get_field( $field_name, 'option' ) : $default;
	}

	/**
	 * Return a policy.
	 *
	 * @param string $policy Policy name.
	 *
	 * @return mixed
	 */
	public static function get_policy( string $policy ): mixed {
		if ( isset( static::$policies[ $policy ] ) ) {
			if ( ! isset( static::$data['policies'][ $policy ] ) ) {
				$field_name                          = $policy;
				static::$data['policies'][ $policy ] = self::get_value( $field_name, static::$policies[ $policy ] );
			}
			return static::$data['policies'][ $policy ];
		}

		return array(
			'enabled' => false,
		);
	}

	/**
	 * Return a permission policy policy.
	 *
	 * @param string $permission Permission policy name.
	 *
	 * @return mixed
	 */
	public static function get_permission_policy( string $permission ): mixed {
		if ( isset( static::$permissions[ $permission ] ) ) {
			if ( ! isset( static::$data['permissions'][ $permission ] ) ) {
				$field_name                                 = $permission;
				static::$data['permissions'][ $permission ] = self::get_value( $field_name, static::$permissions[ $permission ] );
			}
			return static::$data['permissions'][ $permission ];
		}

		return array(
			'enabled' => false,
		);
	}

	/**
	 * Generate and send security headers.
	 *
	 * @return void
	 */
	public static function send_headers() {
		// HSTS enforced for 365 Days.
		if ( static::get( 'security', 'hsts_enable' ) ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}

		// Only use content type headers to validate type.
		if ( static::get( 'security', 'nosniff_enable' ) ) {
			header( 'X-Content-Type-Options: nosniff' );
		}

		// Try to protect against XSS attacks.
		if ( static::get( 'security', 'xss_enable' ) ) {
			header( 'X-XSS-Protection: 1; mode=block' );
		}

		// Explicitly set referrer policy to default value.
		if ( static::get( 'security', 'referrer_enable' ) ) {
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		}

		if ( static::csp_test_mode_enabled() ) {
			$policy = self::build_policy_array();
			header( 'Content-Security-Policy: ' . self::build_policy_string( $policy, "'self' https:" ) );
		} elseif ( static::get( 'security', 'csp_enable' ) ) {
			$policy = get_option( static::POLICY_OPTION_NAME );

			if ( defined( 'SENTRY_SECURITY_ENDPOINT' ) ) {
				header( 'Report-To: {"group":"glitchtip","max_age":10886400,"endpoints":[{"url":' . SENTRY_SECURITY_ENDPOINT . '}],"include_subdomains":true}' );
			}

			if ( empty( $policy ) ) {
				$policy = self::build_policy_array();
				update_option( static::POLICY_OPTION_NAME, $policy );
			}
			// Content Security Policy.
			header( 'Content-Security-Policy: ' . self::build_policy_string( $policy, "'self' https:" ) );
		}

		if ( static::get( 'permissions', 'permissions_enable' ) ) {
			$permissions = self::build_permissions_array();
			header( 'Permissions-Policy: ' . self::build_permission_string( $permissions ) );
		}
	}

	/**
	 * Build the CSP string to be set in HTTP header.
	 *
	 * @param array  $policy Array containing the CSP policies set in backend.
	 * @param string $form Form action policy.
	 * @param string $frame Frame-ancestors policy.
	 *
	 * @return string
	 */
	public static function build_policy_string( $policy, $form = "'self'", $frame = "'self'" ) {
		$string  = "base-uri 'self'; ";
		$string .= "object-src 'none'; ";
		$string .= "form-action $form; ";
		if ( ! empty( $frame ) ) {
			$string .= "frame-ancestors $frame; ";
		}
		foreach ( $policy as $key => $value ) {
			$string .= "{$key}-src $value; ";
		}
		if ( defined( 'SENTRY_SECURITY_ENDPOINT' ) ) {
			$string .= 'report-uri ' . SENTRY_SECURITY_ENDPOINT . '; report-to glitchtip';
		}

		return $string;
	}

	/**
	 * Build the CSP policy array from data set in backend.
	 *
	 * @return array
	 */
	public static function build_policy_array() {
		$built_array = array();
		foreach ( self::$policies as $key => $values ) {
			$policy = self::get_policy( $key );
			if ( ! empty( $policy ) && $policy['enabled'] ) {
				$built_string = '';
				if ( $policy['self'] ) {
					$built_string .= "'self' ";
				}
				if ( $policy['inline'] ) {
					$built_string .= "'unsafe-inline' ";
				}
				if ( $policy['eval'] ) {
					$built_string .= "'unsafe-eval' ";
				}
				if ( $policy['data'] ) {
					$built_string .= 'data: ';
				}
				if ( $policy['wss'] ) {
					$built_string .= 'wss: ';
				}
				if ( $policy['all_https'] ) {
					$built_string .= 'https: ';
				} else {
					$all_urls = static::get( 'security', 'always_allow_urls' );
					if ( ! empty( $policy['allow_urls'] ) ) {
						$built_string .= ' ' . $policy['allow_urls'];
					}
					if ( ! empty( $all_urls ) ) {
						$built_string .= ' ' . $all_urls;
					}
				}
				if ( empty( $built_string ) ) {
					$built_string = "'none'";
				}
				$built_array[ $key ] = $built_string;
			}
		}

		return $built_array;
	}

	/**
	 * Build the Permission Policy string to be set in HTTP header.
	 *
	 * @param array $permissions Array containing the permission policies set in backend.
	 *
	 * @return string
	 */
	public static function build_permission_string( $permissions ) {
		$string = '';
		foreach ( $permissions as $key => $value ) {
			$string .= "{$key}=$value";
			if ( $key !== array_key_last( $permissions ) ) {
				$string .= ', ';
			}
		}
		return $string;
	}

	/**
	 * Build the permission policy array from data set in backend.
	 *
	 * @return array
	 */
	public static function build_permissions_array() {
		$built_array = array();
		foreach ( self::$permissions as $key => $values ) {
			$permission = self::get_permission_policy( $key );
			if ( ! empty( $permission ) && $permission['enabled'] ) {
				$built_string = '';
				if ( $permission['allow_none'] ) {
					$built_string .= '()';
				} elseif ( $permission['allow_all'] ) {
					$built_string .= '*';
				} elseif ( $permission['self'] && ! empty( $permission['allow_urls'] ) ) {
						$built_string .= '(self ';
						$built_string  = self::explode_permission_urls( $permission['allow_urls'], $built_string );
						$built_string .= ')';
				} elseif ( $permission['self'] ) {
					$built_string .= '(self)';
				} elseif ( ! empty( $permission['allow_urls'] ) ) {
					$built_string .= '(';
					$built_string  = self::explode_permission_urls( $permission['allow_urls'], $built_string );
					$built_string .= ')';
				}
				$built_array[ $key ] = $built_string;
			}
		}

		return $built_array;
	}

	/**
	 * Surround permissions urls with "" characters.
	 *
	 * @param string $url_string The string of urls from backend.
	 * @param string $built_string The permission string that is being built.
	 *
	 * @return string
	 */
	public static function explode_permission_urls( $url_string, $built_string ) {
		$url_array = explode( ' ', $url_string );
		foreach ( $url_array as $url ) {
			$built_string .= '"' . $url . '"';
			if ( $url !== end( $url_array ) ) {
				$built_string .= ' ';
			}
		}
		return $built_string;
	}

	/**
	 * Check for test mode and only enable for admins when test mode is on.
	 *
	 * @return bool
	 */
	public static function csp_test_mode_enabled() {
		return static::get( 'security', 'csp_test_mode' ) && current_user_can( 'manage_options' );
	}

	/**
	 * Create ACF fields on security page.
	 *
	 * @return void
	 */
	private static function create_acf() {
		$fields = array();
		foreach ( static::$fields['security']['fields'] as $name => $field ) {
			$fields[] = self::add_field( self::get_field_name( $name, 'security' ), $field );
		}
		foreach ( static::$policies as $name => $policy ) {
			$fields[] = self::add_policy( $name, $policy );
		}

		$fields[] = array(
			'key'     => 'field_63617c2a76fcd',
			'label'   => 'Import',
			'name'    => self::get_field_name( 'import', 'import' ),
			'type'    => 'true_false',
			'wrapper' => array(
				'width' => '50',
			),
			'message' => 'Import Full CSP',
		);
		$fields[] = array(
			'key'               => 'field_63617c3f76fce',
			'label'             => 'Overwrite',
			'name'              => self::get_field_name( 'overwrite', 'import' ),
			'type'              => 'true_false',
			'conditional_logic' => array(
				array(
					array(
						'field'    => 'field_63617c2a76fcd',
						'operator' => '==',
						'value'    => '1',
					),
				),
			),
			'wrapper'           => array(
				'width' => '50',
			),
			'message'           => 'Overwite all old values with the new CSP, leaving this unchecked appends the new values to the existing.',
		);
		$fields[] = array(
			'key'               => 'field_63617c78cd390',
			'label'             => 'CSP',
			'name'              => self::get_field_name( 'csp', 'import' ),
			'type'              => 'textarea',
			'conditional_logic' => array(
				array(
					array(
						'field'    => 'field_63617c2a76fcd',
						'operator' => '==',
						'value'    => '1',
					),
				),
			),
		);

		if ( function_exists( 'acf_add_local_field_group' ) ) {
			acf_add_local_field_group(
				array(
					'key'                   => 'group_security_policy',
					'title'                 => 'Content Security Policy',
					'fields'                => $fields,
					'location'              => array(
						array(
							array(
								'param'    => 'options_page',
								'operator' => '==',
								'value'    => 'security',
							),
						),
					),
					'menu_order'            => 0,
					'position'              => 'normal',
					'style'                 => 'default',
					'label_placement'       => 'top',
					'instruction_placement' => 'label',
					'hide_on_screen'        => '',
					'active'                => true,
					'description'           => '',
					'show_in_rest'          => 0,
				)
			);

			$permission_fields = array();
			foreach ( static::$fields['permissions']['fields'] as $name => $field ) {
				$permission_fields[] = self::add_field( self::get_field_name( $name, 'permissions' ), $field );
			}
			foreach ( static::$permissions as $name => $policy ) {
				$permission_fields[] = self::add_policy( $name, $policy );
			}

			acf_add_local_field_group(
				array(
					'key'                   => 'group_permissions_policy',
					'title'                 => 'Permissions Policy',
					'fields'                => $permission_fields,
					'location'              => array(
						array(
							array(
								'param'    => 'options_page',
								'operator' => '==',
								'value'    => 'security',
							),
						),
					),
					'menu_order'            => 1,
					'position'              => 'normal',
					'style'                 => 'default',
					'label_placement'       => 'top',
					'instruction_placement' => 'label',
					'hide_on_screen'        => '',
					'active'                => true,
					'description'           => '',
					'show_in_rest'          => 0,
				)
			);
		}
	}

	/**
	 * Add acf fields from policy arrays.
	 *
	 * @param string $name The name of the policy group.
	 * @param array  $policy Array of the policies.
	 *
	 * @return array
	 */
	private static function add_policy( string $name, array $policy ) {
		$group_name = self::get_field_name( $name, 'group' );

		$fields = array();
		foreach ( $policy as $key => $value ) {
			if ( 'allow_urls' === $key ) {
				$fields[] = array(
					'key'               => self::get_field_name( $key, $name ),
					'label'             => 'Allow URLs',
					'name'              => $key,
					'type'              => 'text',
					'conditional_logic' => array(
						array(
							array(
								'field'    => self::get_field_name( 'all_https', $name ),
								'operator' => '!=',
								'value'    => '1',
							),
							array(
								'field'    => self::get_field_name( 'allow_all', $name ),
								'operator' => '!=',
								'value'    => '1',
							),
							array(
								'field'    => self::get_field_name( 'allow_none', $name ),
								'operator' => '!=',
								'value'    => '1',
							),
						),
					),
					'wrapper'           => array(
						'width' => '100',
					),
					'default_value'     => $value,
				);
			} else {
				$fields[] = array(
					'key'           => self::get_field_name( $key, $name ),
					'label'         => static::make_label( $key ),
					'name'          => $key,
					'type'          => 'true_false',
					'wrapper'       => array(
						'width' => '14',
					),
					'default_value' => $value,
				);
			}
		}

		return array(
			'key'        => $group_name,
			'label'      => static::make_label( $name ),
			'name'       => $name,
			'type'       => 'group',
			'wrapper'    => array(
				'width' => '',
				'class' => '',
				'id'    => '',
			),
			'layout'     => 'block',
			'sub_fields' => $fields,
		);
	}

	/**
	 * Add the settings page.
	 *
	 * @return void
	 */
	public static function save_settings(): void {
		$screen = get_current_screen();
		if ( 'settings_page_security' === $screen->id ) {
			// Save CSP to option, if not in test mode.
			if ( ! static::get( 'security', 'csp_test_mode' ) ) {
				$policy = self::build_policy_array();
				update_option( static::POLICY_OPTION_NAME, $policy );
			}

			// Get field values.
			$import    = get_field( self::get_field_name( 'import', 'import' ), 'option' );
			$overwrite = get_field( self::get_field_name( 'overwrite', 'import' ), 'option' );
			$csp       = get_field( self::get_field_name( 'csp', 'import' ), 'option' );
			if ( $import ) {
				// Import active.
				$policies = array();
				// Loop all policies.
				foreach ( explode( ';', $csp ) as $record ) {
					// Take the string apart.
					$parts = explode( ' ', trim( $record ) );
					// Remove first element and check if it's a "src" policy.
					$policy_parts = explode( '-', array_shift( $parts ) );
					if ( 'src' === $policy_parts[1] ) {
						// Set the default policy.
						$policy = array(
							'enabled'    => true,
							'self'       => false,
							'inline'     => false,
							'eval'       => false,
							'data'       => false,
							'wss'        => false,
							'all_https'  => false,
							'allow_urls' => '',
						);
						// Loop and populate.
						foreach ( $parts as $part ) {
							switch ( $part ) {
								case "'none'":
									// This shouldn't change anything, default is empty.
									break;
								case "'self'":
									$policy['self'] = true;
									break;
								case "'unsafe-inline'":
									$policy['inline'] = true;
									break;
								case "'unsafe-eval'":
									$policy['eval'] = true;
									break;
								case 'data:':
									$policy['data'] = true;
									break;
								case 'wss:':
									$policy['wss'] = true;
									break;
								case 'https:':
									// This probably never occurs, but it's here just in case.
									$policy['all_https'] = true;
									break;
								default:
									// Add unknown elements to the URL list.
									$policy['allow_urls'] .= ' ' . $part;
									break;
							}
						}
						// Clean up the urls.
						$policy['allow_urls'] = trim( $policy['allow_urls'] );
						// Add the policy to array.
						$policies[ $policy_parts[0] ] = $policy;
					}
				}
				if ( ! empty( $policies ) ) {
					$empty = array(
						'enabled'    => false,
						'self'       => false,
						'inline'     => false,
						'eval'       => false,
						'data'       => false,
						'wss'        => false,
						'all_https'  => false,
						'allow_urls' => '',
					);
					if ( $overwrite ) {
						foreach ( self::$policies as $policy => $default ) {
							if ( isset( $policies[ $policy ] ) ) {
								// Overwrite the policy.
								update_field( self::get_field_name( $policy, 'group' ), $policies[ $policy ], 'option' );
							} else {
								// Empty the policy.
								update_field( self::get_field_name( $policy, 'group' ), $empty, 'option' );
							}
						}
					} else {
						// TODO Merge.
						foreach ( $policies as $policy => $values ) {
							foreach ( self::get_policy( $policy ) as $key => $value ) {
								if ( 'allow_urls' === $key ) {
									$elements       = array_merge(
										explode( ' ', $values[ $key ] ),
										explode( ' ', $value ),
									);
									$values[ $key ] = implode( ' ', array_unique( $elements ) );
								} elseif ( true === $value ) {
									$values[ $key ] = true;
								}
							}
							update_field( self::get_field_name( $policy, 'group' ), $values, 'option' );
						}
					}
				}
				// Empty the values.
				update_field( self::get_field_name( 'import', 'import' ), false, 'option' );
				update_field( self::get_field_name( 'overwrite', 'import' ), false, 'option' );
				update_field( self::get_field_name( 'csp', 'import' ), '', 'option' );
			}
		}
	}

	/**
	 * Helper function for adding ACF fields.
	 *
	 * @param string $name Name of the field/setting.
	 * @param array  $field Array of settings for the field.
	 *
	 * @return array
	 */
	private static function add_field( string $name, array $field ): array {
		return array(
			'key'           => $name,
			'label'         => $field['label'],
			'name'          => $name,
			'type'          => $field['type'],
			'instructions'  => '',
			'required'      => 0,
			'wrapper'       => array(
				'width' => $field['width'] ?? '100',
				'class' => '',
				'id'    => '',
			),
			'default_value' => $field['default'],
		);
	}

	/**
	 * Helper function to uppercase the labels in security settings.
	 *
	 * @param string $label The label to be uppercased.
	 *
	 * @return string
	 */
	private static function make_label( string $label ): string {
		return ucwords( str_replace( '_', ' ', $label ) );
	}
}
