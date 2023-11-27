class PostgresqlAT16 < Formula
  desc "Object-relational database system"
  homepage "https://www.postgresql.org/"
  url "https://ftp.postgresql.org/pub/source/v16.1/postgresql-16.1.tar.bz2"
  sha256 "ce3c4d85d19b0121fe0d3f8ef1fa601f71989e86f8a66f7dc3ad546dd5564fec"
  license "PostgreSQL"
  revision 1

  livecheck do
    url "https://ftp.postgresql.org/pub/source/"
    regex(%r{href=["']?v?(16(?:\.\d+)+)/?["' >]}i)
  end

  bottle do
    sha256 arm64_sonoma:   "eedffe1339b4940f09c15735d0841deed17c82c7e91b7d2688a873730dadd786"
    sha256 arm64_ventura:  "2d15551d9fe0774d6bf9d6ed447665a6b160b26d17982bde3790404a5a4f1ce1"
    sha256 arm64_monterey: "07d53f3d1c4ebb47d130992e31be1bc7136e10543cad68379c90366c16747b9e"
    sha256 sonoma:         "a06edc24e315fe05ad8f21f675cbaae97df022d65124eb9069a038e64bb760c5"
    sha256 ventura:        "930dc19ed891f87a73b66f4405ee9f0ab678375f2f105e7f53b25c0645958e77"
    sha256 monterey:       "e08c209e89b5f3269be496c42d44fbced3f3d721c093555e5da1c64527184823"
    sha256 x86_64_linux:   "793145f071633c4c4d00198cd4722abf3f4cc0184f728e6b2b0d3dbf11431f83"
  end

  keg_only :versioned_formula

  # https://www.postgresql.org/support/versioning/
  deprecate! date: "2028-11-09", because: :unsupported

  depends_on "pkg-config" => :build
  depends_on "gettext"
  depends_on "icu4c"

  # GSSAPI provided by Kerberos.framework crashes when forked.
  # See https://github.com/Homebrew/homebrew-core/issues/47494.
  depends_on "krb5"

  depends_on "lz4"
  depends_on "openssl@3"
  depends_on "readline"

  uses_from_macos "libxml2"
  uses_from_macos "libxslt"
  uses_from_macos "openldap"
  uses_from_macos "perl"

  on_linux do
    depends_on "linux-pam"
    depends_on "util-linux"
  end

  # Fix compatibility with OpenSSL 3.2
  # Remove once merged
  # Ref https://www.postgresql.org/message-id/CX9SU44GH3P4.17X6ZZUJ5D40N%40neon.tech
  patch :DATA

  def install
    ENV.delete "PKG_CONFIG_LIBDIR"
    ENV.prepend "LDFLAGS", "-L#{Formula["openssl@3"].opt_lib} -L#{Formula["readline"].opt_lib}"
    ENV.prepend "CPPFLAGS", "-I#{Formula["openssl@3"].opt_include} -I#{Formula["readline"].opt_include}"

    # Fix 'libintl.h' file not found for extensions
    ENV.prepend "LDFLAGS", "-L#{Formula["gettext"].opt_lib}"
    ENV.prepend "CPPFLAGS", "-I#{Formula["gettext"].opt_include}"

    args = std_configure_args + %W[
      --datadir=#{opt_pkgshare}
      --libdir=#{opt_lib}
      --includedir=#{opt_include}
      --sysconfdir=#{etc}
      --docdir=#{doc}
      --enable-nls
      --enable-thread-safety
      --with-gssapi
      --with-icu
      --with-ldap
      --with-libxml
      --with-libxslt
      --with-lz4
      --with-openssl
      --with-pam
      --with-perl
      --with-uuid=e2fs
      --with-extra-version=\ (#{tap.user})
    ]
    if OS.mac?
      args += %w[
        --with-bonjour
        --with-tcl
      ]
    end

    # PostgreSQL by default uses xcodebuild internally to determine this,
    # which does not work on CLT-only installs.
    args << "PG_SYSROOT=#{MacOS.sdk_path}" if MacOS.sdk_root_needed?

    system "./configure", *args

    # Work around busted path magic in Makefile.global.in. This can't be specified
    # in ./configure, but needs to be set here otherwise install prefixes containing
    # the string "postgres" will get an incorrect pkglibdir.
    # See https://github.com/Homebrew/homebrew-core/issues/62930#issuecomment-709411789
    system "make", "pkglibdir=#{opt_lib}/postgresql",
                   "pkgincludedir=#{opt_include}/postgresql",
                   "includedir_server=#{opt_include}/postgresql/server"
    system "make", "install-world", "datadir=#{pkgshare}",
                                    "libdir=#{lib}",
                                    "pkglibdir=#{lib}/postgresql",
                                    "includedir=#{include}",
                                    "pkgincludedir=#{include}/postgresql",
                                    "includedir_server=#{include}/postgresql/server",
                                    "includedir_internal=#{include}/postgresql/internal"
  end

  def post_install
    (var/"log").mkpath
    postgresql_datadir.mkpath

    # Don't initialize database, it clashes when testing other PostgreSQL versions.
    return if ENV["HOMEBREW_GITHUB_ACTIONS"]

    system "#{bin}/initdb", "--locale=C", "-E", "UTF-8", postgresql_datadir unless pg_version_exists?
  end

  def postgresql_datadir
    var/name
  end

  def postgresql_log_path
    var/"log/#{name}.log"
  end

  def pg_version_exists?
    (postgresql_datadir/"PG_VERSION").exist?
  end

  def caveats
    <<~EOS
      This formula has created a default database cluster with:
        initdb --locale=C -E UTF-8 #{postgresql_datadir}
      For more details, read:
        https://www.postgresql.org/docs/#{version.major}/app-initdb.html
    EOS
  end

  service do
    run [opt_bin/"postgres", "-D", f.postgresql_datadir]
    environment_variables LC_ALL: "C"
    keep_alive true
    log_path f.postgresql_log_path
    error_log_path f.postgresql_log_path
    working_dir HOMEBREW_PREFIX
  end

  test do
    system "#{bin}/initdb", testpath/"test" unless ENV["HOMEBREW_GITHUB_ACTIONS"]
    assert_equal opt_pkgshare.to_s, shell_output("#{bin}/pg_config --sharedir").chomp
    assert_equal opt_lib.to_s, shell_output("#{bin}/pg_config --libdir").chomp
    assert_equal (opt_lib/"postgresql").to_s, shell_output("#{bin}/pg_config --pkglibdir").chomp
    assert_equal (opt_include/"postgresql").to_s, shell_output("#{bin}/pg_config --pkgincludedir").chomp
    assert_equal (opt_include/"postgresql/server").to_s, shell_output("#{bin}/pg_config --includedir-server").chomp
    assert_match "-I#{Formula["gettext"].opt_include}", shell_output("#{bin}/pg_config --cppflags")
  end
end

__END__
diff --git a/configure b/configure
index 82e45657b2..907c777b9c 100755
--- a/configure
+++ b/configure
@@ -12982,7 +12982,7 @@ done
   # defines OPENSSL_VERSION_NUMBER to claim version 2.0.0, even though it
   # doesn't have these OpenSSL 1.1.0 functions. So check for individual
   # functions.
-  for ac_func in OPENSSL_init_ssl BIO_get_data BIO_meth_new ASN1_STRING_get0_data HMAC_CTX_new HMAC_CTX_free
+  for ac_func in OPENSSL_init_ssl BIO_meth_new ASN1_STRING_get0_data HMAC_CTX_new HMAC_CTX_free
 do :
   as_ac_var=`$as_echo "ac_cv_func_$ac_func" | $as_tr_sh`
 ac_fn_c_check_func "$LINENO" "$ac_func" "$as_ac_var"
diff --git a/configure.ac b/configure.ac
index fcea0bcab4..ab32bfdd08 100644
--- a/configure.ac
+++ b/configure.ac
@@ -1385,7 +1385,7 @@ if test "$with_ssl" = openssl ; then
   # defines OPENSSL_VERSION_NUMBER to claim version 2.0.0, even though it
   # doesn't have these OpenSSL 1.1.0 functions. So check for individual
   # functions.
-  AC_CHECK_FUNCS([OPENSSL_init_ssl BIO_get_data BIO_meth_new ASN1_STRING_get0_data HMAC_CTX_new HMAC_CTX_free])
+  AC_CHECK_FUNCS([OPENSSL_init_ssl BIO_meth_new ASN1_STRING_get0_data HMAC_CTX_new HMAC_CTX_free])
   # OpenSSL versions before 1.1.0 required setting callback functions, for
   # thread-safety. In 1.1.0, it's no longer required, and CRYPTO_lock()
   # function was removed.
diff --git a/meson.build b/meson.build
index 51b5285924..96fc2e139a 100644
--- a/meson.build
+++ b/meson.build
@@ -1278,7 +1278,6 @@ if sslopt in ['auto', 'openssl']
       # doesn't have these OpenSSL 1.1.0 functions. So check for individual
       # functions.
       ['OPENSSL_init_ssl'],
-      ['BIO_get_data'],
       ['BIO_meth_new'],
       ['ASN1_STRING_get0_data'],
       ['HMAC_CTX_new'],
diff --git a/src/backend/libpq/be-secure-openssl.c b/src/backend/libpq/be-secure-openssl.c
index e9c86d08df..49dca0cda9 100644
--- a/src/backend/libpq/be-secure-openssl.c
+++ b/src/backend/libpq/be-secure-openssl.c
@@ -844,11 +844,6 @@ be_tls_write(Port *port, void *ptr, size_t len, int *waitfor)
  * to retry; do we need to adopt their logic for that?
  */

-#ifndef HAVE_BIO_GET_DATA
-#define BIO_get_data(bio) (bio->ptr)
-#define BIO_set_data(bio, data) (bio->ptr = data)
-#endif
-
 static BIO_METHOD *my_bio_methods = NULL;

 static int
@@ -858,7 +853,7 @@ my_sock_read(BIO *h, char *buf, int size)

 	if (buf != NULL)
 	{
-		res = secure_raw_read(((Port *) BIO_get_data(h)), buf, size);
+		res = secure_raw_read(((Port *) BIO_get_app_data(h)), buf, size);
 		BIO_clear_retry_flags(h);
 		if (res <= 0)
 		{
@@ -878,7 +873,7 @@ my_sock_write(BIO *h, const char *buf, int size)
 {
 	int			res = 0;

-	res = secure_raw_write(((Port *) BIO_get_data(h)), buf, size);
+	res = secure_raw_write(((Port *) BIO_get_app_data(h)), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res <= 0)
 	{
@@ -954,7 +949,7 @@ my_SSL_set_fd(Port *port, int fd)
 		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
 		goto err;
 	}
-	BIO_set_data(bio, port);
+	BIO_set_app_data(bio, port);

 	BIO_set_fd(bio, fd, BIO_NOCLOSE);
 	SSL_set_bio(port->ssl, bio, bio);
diff --git a/src/include/pg_config.h.in b/src/include/pg_config.h.in
index 6d572c3820..174544630e 100644
--- a/src/include/pg_config.h.in
+++ b/src/include/pg_config.h.in
@@ -70,9 +70,6 @@
 /* Define to 1 if you have the `backtrace_symbols' function. */
 #undef HAVE_BACKTRACE_SYMBOLS

-/* Define to 1 if you have the `BIO_get_data' function. */
-#undef HAVE_BIO_GET_DATA
-
 /* Define to 1 if you have the `BIO_meth_new' function. */
 #undef HAVE_BIO_METH_NEW

diff --git a/src/interfaces/libpq/fe-secure-openssl.c b/src/interfaces/libpq/fe-secure-openssl.c
index 390c888c96..b730352b86 100644
--- a/src/interfaces/libpq/fe-secure-openssl.c
+++ b/src/interfaces/libpq/fe-secure-openssl.c
@@ -1830,11 +1830,6 @@ PQsslAttribute(PGconn *conn, const char *attribute_name)
  * to retry; do we need to adopt their logic for that?
  */

-#ifndef HAVE_BIO_GET_DATA
-#define BIO_get_data(bio) (bio->ptr)
-#define BIO_set_data(bio, data) (bio->ptr = data)
-#endif
-
 static BIO_METHOD *my_bio_methods;

 static int
@@ -1842,7 +1837,7 @@ my_sock_read(BIO *h, char *buf, int size)
 {
 	int			res;

-	res = pqsecure_raw_read((PGconn *) BIO_get_data(h), buf, size);
+	res = pqsecure_raw_read((PGconn *) BIO_get_app_data(h), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res < 0)
 	{
@@ -1872,7 +1867,7 @@ my_sock_write(BIO *h, const char *buf, int size)
 {
 	int			res;

-	res = pqsecure_raw_write((PGconn *) BIO_get_data(h), buf, size);
+	res = pqsecure_raw_write((PGconn *) BIO_get_app_data(h), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res < 0)
 	{
@@ -1963,7 +1958,7 @@ my_SSL_set_fd(PGconn *conn, int fd)
 		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
 		goto err;
 	}
-	BIO_set_data(bio, conn);
+	BIO_set_app_data(bio, conn);

 	SSL_set_bio(conn->ssl, bio, bio);
 	BIO_set_fd(bio, fd, BIO_NOCLOSE);
diff --git a/src/tools/msvc/Solution.pm b/src/tools/msvc/Solution.pm
index b6d31c3583..711fae853f 100644
--- a/src/tools/msvc/Solution.pm
+++ b/src/tools/msvc/Solution.pm
@@ -225,7 +225,6 @@ sub GenerateFiles
 		HAVE_ATOMICS => 1,
 		HAVE_ATOMIC_H => undef,
 		HAVE_BACKTRACE_SYMBOLS => undef,
-		HAVE_BIO_GET_DATA => undef,
 		HAVE_BIO_METH_NEW => undef,
 		HAVE_COMPUTED_GOTO => undef,
 		HAVE_COPYFILE => undef,
@@ -503,7 +502,6 @@ sub GenerateFiles
 			|| ($digit1 >= '1' && $digit2 >= '1' && $digit3 >= '0'))
 		{
 			$define{HAVE_ASN1_STRING_GET0_DATA} = 1;
-			$define{HAVE_BIO_GET_DATA} = 1;
 			$define{HAVE_BIO_METH_NEW} = 1;
 			$define{HAVE_HMAC_CTX_FREE} = 1;
 			$define{HAVE_HMAC_CTX_NEW} = 1;
