class PostgresqlAT13 < Formula
  desc "Object-relational database system"
  homepage "https://www.postgresql.org/"
  url "https://ftp.postgresql.org/pub/source/v13.13/postgresql-13.13.tar.bz2"
  sha256 "8af69c2599047a2ad246567d68ec4131aef116954d8c3e469e9789080b37a474"
  license "PostgreSQL"
  revision 1

  livecheck do
    url "https://ftp.postgresql.org/pub/source/"
    regex(%r{href=["']?v?(13(?:\.\d+)+)/?["' >]}i)
  end

  bottle do
    sha256 arm64_sonoma:   "421da87133f989c4d8915e319f84a9d4a6686c0512e338c0f301e1653ecd41de"
    sha256 arm64_ventura:  "2251780ee8e54790ef305e5d590da6ab169739354a12c6b8a86f1b6be29f79aa"
    sha256 arm64_monterey: "d8f4ff9a5d5faf6d91b6a64d7f2fbf6f26a9f4fdf046887203738dc2a4a2fca3"
    sha256 sonoma:         "a3a04c7408dc5816d72b57f857634f6a57ed150429a1aaeb38d13a29be9b40ea"
    sha256 ventura:        "ae0467af5251d11f620a29e658f56e3d96962d00b2624317c0def6bc9729ad35"
    sha256 monterey:       "9b0315df47bc7c663b6b33fbb874573418a8557de815e346953aadfb5c642d3e"
    sha256 x86_64_linux:   "044f9b67e443a3f3e7872c3a7668438754862ca18ead35b4b78361f9c4b61664"
  end

  keg_only :versioned_formula

  # https://www.postgresql.org/support/versioning/
  deprecate! date: "2025-11-13", because: :unsupported

  depends_on "pkg-config" => :build
  depends_on "icu4c"

  # GSSAPI provided by Kerberos.framework crashes when forked.
  # See https://github.com/Homebrew/homebrew-core/issues/47494.
  depends_on "krb5"

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
    ENV.delete "PKG_CONFIG_LIBDIR" if MacOS.version == :catalina
    ENV.prepend "LDFLAGS", "-L#{Formula["openssl@3"].opt_lib} -L#{Formula["readline"].opt_lib}"
    ENV.prepend "CPPFLAGS", "-I#{Formula["openssl@3"].opt_include} -I#{Formula["readline"].opt_include}"

    args = %W[
      --disable-debug
      --prefix=#{prefix}
      --datadir=#{opt_pkgshare}
      --libdir=#{opt_lib}
      --includedir=#{opt_include}
      --sysconfdir=#{etc}
      --docdir=#{doc}
      --enable-thread-safety
      --with-gssapi
      --with-icu
      --with-ldap
      --with-libxml
      --with-libxslt
      --with-openssl
      --with-pam
      --with-perl
      --with-uuid=e2fs
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

    if OS.linux?
      inreplace lib/"postgresql/pgxs/src/Makefile.global",
                "LD = #{HOMEBREW_PREFIX}/Homebrew/Library/Homebrew/shims/linux/super/ld",
                "LD = #{HOMEBREW_PREFIX}/bin/ld"
    end
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

  def old_postgres_data_dir
    var/"postgres"
  end

  # Figure out what version of PostgreSQL the old data dir is
  # using
  def old_postgresql_datadir_version
    pg_version = old_postgres_data_dir/"PG_VERSION"
    pg_version.exist? && pg_version.read.chomp
  end

  def caveats
    caveats = ""

    # Extract the version from the formula name
    pg_formula_version = version.major.to_s
    # ... and check it against the old data dir postgres version number
    # to see if we need to print a warning re: data dir
    if old_postgresql_datadir_version == pg_formula_version
      caveats += <<~EOS
        Previous versions of postgresql shared the same data directory.

        You can migrate to a versioned data directory by running:
          mv -v "#{old_postgres_data_dir}" "#{postgresql_datadir}"

        (Make sure PostgreSQL is stopped before executing this command)

      EOS
    end

    caveats += <<~EOS
      This formula has created a default database cluster with:
        initdb --locale=C -E UTF-8 #{postgresql_datadir}
      For more details, read:
        https://www.postgresql.org/docs/#{version.major}/app-initdb.html
    EOS

    caveats
  end

  service do
    run [opt_bin/"postgres", "-D", f.postgresql_datadir]
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
  end
end

__END__
diff --git a/configure b/configure
index 2fc7dca504..3062289192 100755
--- a/configure
+++ b/configure
@@ -12713,7 +12713,7 @@ done
   # defines OPENSSL_VERSION_NUMBER to claim version 2.0.0, even though it
   # doesn't have these OpenSSL 1.1.0 functions. So check for individual
   # functions.
-  for ac_func in OPENSSL_init_ssl BIO_get_data BIO_meth_new ASN1_STRING_get0_data
+  for ac_func in OPENSSL_init_ssl BIO_meth_new ASN1_STRING_get0_data
 do :
   as_ac_var=`$as_echo "ac_cv_func_$ac_func" | $as_tr_sh`
 ac_fn_c_check_func "$LINENO" "$ac_func" "$as_ac_var"
diff --git a/configure.in b/configure.in
index eaca132607..f0567efa0e 100644
--- a/configure.in
+++ b/configure.in
@@ -1275,7 +1275,7 @@ if test "$with_openssl" = yes ; then
   # defines OPENSSL_VERSION_NUMBER to claim version 2.0.0, even though it
   # doesn't have these OpenSSL 1.1.0 functions. So check for individual
   # functions.
-  AC_CHECK_FUNCS([OPENSSL_init_ssl BIO_get_data BIO_meth_new ASN1_STRING_get0_data])
+  AC_CHECK_FUNCS([OPENSSL_init_ssl BIO_meth_new ASN1_STRING_get0_data])
   # OpenSSL versions before 1.1.0 required setting callback functions, for
   # thread-safety. In 1.1.0, it's no longer required, and CRYPTO_lock()
   # function was removed.
diff --git a/src/backend/libpq/be-secure-openssl.c b/src/backend/libpq/be-secure-openssl.c
index 55fe59276a..76ef7afd77 100644
--- a/src/backend/libpq/be-secure-openssl.c
+++ b/src/backend/libpq/be-secure-openssl.c
@@ -748,10 +748,6 @@ be_tls_write(Port *port, void *ptr, size_t len, int *waitfor)
  * to retry; do we need to adopt their logic for that?
  */

-#ifndef HAVE_BIO_GET_DATA
-#define BIO_get_data(bio) (bio->ptr)
-#define BIO_set_data(bio, data) (bio->ptr = data)
-#endif

 static BIO_METHOD *my_bio_methods = NULL;

@@ -762,7 +758,7 @@ my_sock_read(BIO *h, char *buf, int size)

 	if (buf != NULL)
 	{
-		res = secure_raw_read(((Port *) BIO_get_data(h)), buf, size);
+		res = secure_raw_read(((Port *) BIO_get_app_data(h)), buf, size);
 		BIO_clear_retry_flags(h);
 		if (res <= 0)
 		{
@@ -782,7 +778,7 @@ my_sock_write(BIO *h, const char *buf, int size)
 {
 	int			res = 0;

-	res = secure_raw_write(((Port *) BIO_get_data(h)), buf, size);
+	res = secure_raw_write(((Port *) BIO_get_app_data(h)), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res <= 0)
 	{
@@ -858,7 +854,7 @@ my_SSL_set_fd(Port *port, int fd)
 		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
 		goto err;
 	}
-	BIO_set_data(bio, port);
+	BIO_set_app_data(bio, port);

 	BIO_set_fd(bio, fd, BIO_NOCLOSE);
 	SSL_set_bio(port->ssl, bio, bio);
diff --git a/src/include/pg_config.h.in b/src/include/pg_config.h.in
index 13fc4e0db6..978e685c70 100644
--- a/src/include/pg_config.h.in
+++ b/src/include/pg_config.h.in
@@ -86,9 +86,6 @@
 /* Define to 1 if you have the `backtrace_symbols' function. */
 #undef HAVE_BACKTRACE_SYMBOLS

-/* Define to 1 if you have the `BIO_get_data' function. */
-#undef HAVE_BIO_GET_DATA
-
 /* Define to 1 if you have the `BIO_meth_new' function. */
 #undef HAVE_BIO_METH_NEW

diff --git a/src/interfaces/libpq/fe-secure-openssl.c b/src/interfaces/libpq/fe-secure-openssl.c
index 07d5daf4d9..1eb17dd280 100644
--- a/src/interfaces/libpq/fe-secure-openssl.c
+++ b/src/interfaces/libpq/fe-secure-openssl.c
@@ -1602,10 +1602,6 @@ PQsslAttribute(PGconn *conn, const char *attribute_name)
  * to retry; do we need to adopt their logic for that?
  */

-#ifndef HAVE_BIO_GET_DATA
-#define BIO_get_data(bio) (bio->ptr)
-#define BIO_set_data(bio, data) (bio->ptr = data)
-#endif

 static BIO_METHOD *my_bio_methods;

@@ -1614,7 +1610,7 @@ my_sock_read(BIO *h, char *buf, int size)
 {
 	int			res;

-	res = pqsecure_raw_read((PGconn *) BIO_get_data(h), buf, size);
+	res = pqsecure_raw_read((PGconn *) BIO_get_app_data(h), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res < 0)
 	{
@@ -1644,7 +1640,7 @@ my_sock_write(BIO *h, const char *buf, int size)
 {
 	int			res;

-	res = pqsecure_raw_write((PGconn *) BIO_get_data(h), buf, size);
+	res = pqsecure_raw_write((PGconn *) BIO_get_app_data(h), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res < 0)
 	{
@@ -1735,7 +1731,7 @@ my_SSL_set_fd(PGconn *conn, int fd)
 		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
 		goto err;
 	}
-	BIO_set_data(bio, conn);
+	BIO_set_app_data(bio, conn);

 	SSL_set_bio(conn->ssl, bio, bio);
 	BIO_set_fd(bio, fd, BIO_NOCLOSE);
diff --git a/src/tools/msvc/Solution.pm b/src/tools/msvc/Solution.pm
index 78328e1fac..e88e3967cd 100644
--- a/src/tools/msvc/Solution.pm
+++ b/src/tools/msvc/Solution.pm
@@ -226,7 +226,6 @@ sub GenerateFiles
 		HAVE_ATOMICS               => 1,
 		HAVE_ATOMIC_H              => undef,
 		HAVE_BACKTRACE_SYMBOLS     => undef,
-		HAVE_BIO_GET_DATA          => undef,
 		HAVE_BIO_METH_NEW          => undef,
 		HAVE_CLOCK_GETTIME         => undef,
 		HAVE_COMPUTED_GOTO         => undef,
@@ -543,7 +542,6 @@ sub GenerateFiles
 			|| ($digit1 >= '1' && $digit2 >= '1' && $digit3 >= '0'))
 		{
 			$define{HAVE_ASN1_STRING_GET0_DATA} = 1;
-			$define{HAVE_BIO_GET_DATA}          = 1;
 			$define{HAVE_BIO_METH_NEW}          = 1;
 			$define{HAVE_OPENSSL_INIT_SSL}      = 1;
 		}
