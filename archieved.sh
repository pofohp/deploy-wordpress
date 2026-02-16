# Add the following line to the end of C:\Windows\System32\drivers\etc\hosts
# Keep a blank line at the end
192.168.242.129 domain.com
# If the domain’s CDN is not taking effect, try flushing the DNS cache or changing your DNS servers to 8.8.8.8 and 1.1.1.1.
ipconfig /flushdns
# If the site fails to load initially, try the following based on the type of website:
# For local websites, use a mobile hotspot with VPN turned off to check if the issue is related to your local network.
# For public websites, try enabling VPN and switching to whitelist or global mode to bypass potential network restrictions.

# Access WordPress at
domain.com
# Admin login URL by default
https://domain.com/wp-login.php

admin@example.com

# Check Site Health under Tools and try uploading/downloading files

# Use the plugin "WPS Hide Login" to change the default login URL

# To allow uploading different file types, add the following to your theme's functions.php
sudo nano /var/www/wordpress/wp-content/themes/twentytwentyfive/functions.php 还要考虑 php 和 nginx 的默认允许上传大小，超了也会报错，可以先上传一个小文件试试看。zip 和 rar 是默认 可以上传的。
# php.ini → upload_max_filesize 和 post_max_size ，Nginx，检查 client_max_body_size
# functions.php 已经在用 upload_mimes 过滤器了，只要在 $mimes 数组里多加一行 zip 就可以了。（但是实际上 本身已经支持 zip 和 rar 上传了）
# $mimes['zip'] = 'application/zip';  // 新增 zip 上传
# 有些主机（比如 Apache + PHP）还会在 php.ini 或 web 服务器层面禁止 .zip 上传，
# 如果你要上传的 zip 很大，还需要在 Nginx/Apache 配置里放宽限制。
# 现在可以了 我想知道为啥 $mimes['zip'] = 'application/zip'; zip 后面就直接是 zip ，而 exe 要加个 application/x-msdownload 里的 x-msdownload ，sh 也是 x-sh
# MIME 类型（媒体类型）是 Web 服务器和浏览器之间用来指示文件类型的标准
# 它主要分为两类：

主类型（Main Type）：像 application、text、image 这些大类。

子类型（Sub Type）：进一步指定文件的具体类型，如 application/zip 或 image/png。
为什么 zip 直接是 application/zip

ZIP 文件本身就是一个标准的 压缩格式，在 MIME 类型中，已经有专门的定义：application/zip。

这个类型本身就很通用，且符合规范，浏览器和服务器会根据这个类型正确识别和处理 zip 文件。
为什么 exe 和 sh 要加 x-？

application/x-msdownload 和 application/x-sh 里的 x- 代表“非标准扩展类型”。

x- 之前在早期的 MIME 类型定义中，常常用来标识自定义的、没有正式标准的文件类型。

application/x-msdownload：这是 Windows 系统下的可执行文件类型，msdownload 用来特指 Windows 系统上的 .exe 文件。

application/x-sh：是 Shell 脚本文件的 MIME 类型，x-sh 用于指代 Unix/Linux 系统下的 .sh 脚本文件。

总结

zip 属于广泛认定的标准 MIME 类型，所以直接用 application/zip。

exe 和 sh 属于一些系统特定的类型，使用了 x- 以表示这些类型并非标准 MIME 类型，而是由操作系统（如 Windows 或 Linux）定义的扩展类型。

所以，MIME 类型的定义就是为了让浏览器和服务器知道该如何正确处理文件。标准类型直接使用，而扩展类型则需要通过 x- 来表示自定义格式。

在早期，MIME 类型标准并没有为 .exe 文件指定一个统一的类型，所以微软用了一个 x- 开头的扩展 MIME 类型来表示它。

x-msdownload 让服务器和浏览器知道这个文件是 Windows 可执行文件，需要通过操作系统的执行环境来处理，而不是直接由浏览器打开。
那这里不写 msdownload ，随便自己起个名字 比如 $mimes['exe'] = 'application/x-custom'; 可以吗

理论上是可以的，PHP 和 WordPress 都不会阻止你设置自定义的 MIME 类型，但这样做可能会导致一些问题。以下是详细的说明：

可以自己定义 MIME 类型，但有一些考虑：

标准与兼容性问题
如果你将 MIME 类型改成 application/x-custom，浏览器和服务器可能无法正确识别和处理文件。例如，.exe 文件通常会被浏览器以 application/x-msdownload 类型处理，并提示用户下载或执行。如果你改为 application/x-custom，浏览器可能无法识别它，并且不会按预期行为处理文件。

安全问题
application/x-msdownload 这样的类型已经在系统中定义，它的行为是经过深思熟虑的，能够确保文件的安全性和用户的正确体验。如果你自己定义一个类型，可能会绕过一些安全检查，导致不必要的风险，尤其是涉及文件上传的场景。比如，恶意文件可能被误标为“合法文件”并上传。

Web 服务器和操作系统的支持
一些 Web 服务器（如 Apache 或 Nginx）可能根据 MIME 类型来决定文件的处理方式。例如，application/x-msdownload 可能会与 Windows 操作系统中的 .exe 文件关联，自动触发文件下载。自定义的 MIME 类型（如 application/x-custom）可能没有这样的处理机制，导致文件不能正确下载或执行。

WordPress 或其他平台的兼容性
在 WordPress 等平台上，上传和处理文件时，也有可能依赖 MIME 类型来判定文件是否允许上传。自定义类型可能会让某些功能不兼容或者无法正确实现。

是否可以自定义？

是的，可以 通过：

$mimes['exe'] = 'application/x-custom';


但是你需要考虑到：

浏览器的兼容性：浏览器是否能正确处理这种类型。

文件的正确解析和安全性：确保上传的文件不会被误处理为危险文件。

上传限制：WordPress 和 Web 服务器可能会阻止不常见的 MIME 类型。

推荐做法

如果你只想允许 .exe 文件上传，最好的做法还是使用 标准的 MIME 类型，例如 application/x-msdownload。如果你有特殊需求，可以使用自定义类型，但需要考虑安全性和可兼容性。

: <<'END'
function allow_dangerous_uploads($mimes) {
    $mimes['sh']  = 'application/x-sh';
    $mimes['exe'] = 'application/x-msdownload';
    return $mimes;
}
add_filter('upload_mimes', 'allow_dangerous_uploads');

// Only allow unfiltered uploads for admins
define('ALLOW_UNFILTERED_UPLOADS', true);

END

# To change the displayed username in WordPress to show the nickname instead of the login name, go to Users > Profile (or Edit), update the Nickname field,
# and then set “Display name publicly as” to the nickname.

# Allow only logged-in users with stealth options
sudo nano /var/www/wordpress/wp-content/themes/twentytwentyfive/functions.php

: <<'END'
function restrict_access_mode() {
	$mode = 'silent'; // Options: silent, text, 404_template, redirect, external_redirect
	
	if (
		!is_user_logged_in() &&
		!in_array($GLOBALS['pagenow'], ['wp-login.php', 'wp-register.php']) &&
		!is_admin()
	) {
		switch ($mode) {
			case 'silent':  // Blank page + 404 (like the dark web)
				status_header(404);
				nocache_headers();
				exit;
			case 'text':  // Plain text + 404
				status_header(404);
				nocache_headers();
				echo '404 Not Found';
				exit;
			case '404_template':  // Load theme 404 template
				global $wp_query;
				$wp_query->set_404();
				status_header(404);
				nocache_headers();
				include(get_404_template());
				exit;
			case 'redirect':  // Redirect to login
				auth_redirect();
				exit;
			case 'external_redirect':
				// Redirect to Bing with default 302 status (temporary redirect).
				// wp_redirect('https://www.bing.com');
				
				// To make it permanent (301), add ", 301" as the second argument.
				// 301 means browser caches the redirect and next time won’t request the old URL.
				wp_redirect('https://www.bing.com', 301);
				exit;
		}
	}
}

add_action('template_redirect', 'restrict_access_mode');

END











编辑 wp-config.php 在所有内容的最后添加一个
// 动态设置 WordPress URL，保留当前请求端口
$schema = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https://' : 'http://';
$host = $_SERVER['HTTP_HOST'];
define('WP_HOME', $schema . $host);
define('WP_SITEURL', $schema . $host);







