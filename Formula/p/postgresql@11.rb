class PostgresqlAT11 < Formula
  desc "Object-relational database system"
  homepage "https://www.postgresql.org/"
  url "https://ftp.postgresql.org/pub/source/v11.22/postgresql-11.22.tar.bz2"
  sha256 "2cb7c97d7a0d7278851bbc9c61f467b69c094c72b81740b751108e7892ebe1f0"
  license "PostgreSQL"
  revision 1

  bottle do
    sha256 arm64_sonoma:   "3a8e0f24e7e667923d8a7621dd7739b2124b49e85a1e287b4751ba9b046bc5ab"
    sha256 arm64_ventura:  "a181708cda06eede952b82c103a81f0d8b103b543330827625b965e091ec2323"
    sha256 arm64_monterey: "0748465c7dd9909b5ef03dfe47e428901245bc3059c56473ec700a3fea89f3c4"
    sha256 sonoma:         "c99a7b5f10cab76e5ea4b7c0e86c220c7ce544cb30c08ae7cc784366aabc15e8"
    sha256 ventura:        "c9d738f5575ae0931c9cfa545ce40af81b710c5d9201a420a9a1c8c684a4d0b7"
    sha256 monterey:       "1014b72d07473cf85b9267efc08a1573a584bb32f98a4057119b716e336b4fe6"
    sha256 x86_64_linux:   "e55ea45e7f80336d72859cb1076f49e2a0ee4748560d46dd7c40d3d79ddfcde7"
  end

  keg_only :versioned_formula

  # https://www.postgresql.org/support/versioning/
  deprecate! date: "2023-11-09", because: :unsupported

  depends_on "pkg-config" => :build
  depends_on "icu4c"
  depends_on "openssl@3"
  depends_on "readline"

  uses_from_macos "krb5"
  uses_from_macos "libxml2"
  uses_from_macos "libxslt"
  uses_from_macos "openldap"
  uses_from_macos "perl"

  on_linux do
    depends_on "linux-pam"
    depends_on "util-linux"
  end

  # Fix compatibility with OpenSSL 3.2
  # Ref https://www.postgresql.org/message-id/CX9SU44GH3P4.17X6ZZUJ5D40N%40neon.tech
  patch :DATA

  def install
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
    system "make"
    system "make", "install-world", "datadir=#{pkgshare}",
                                    "libdir=#{lib}",
                                    "pkglibdir=#{lib}",
                                    "includedir=#{include}",
                                    "pkgincludedir=#{include}",
                                    "includedir_server=#{include}/server",
                                    "includedir_internal=#{include}/internal"

    if OS.linux?
      inreplace lib/"pgxs/src/Makefile.global",
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
    keep_alive true
    log_path f.postgresql_log_path
    error_log_path f.postgresql_log_path
    working_dir HOMEBREW_PREFIX
  end

  test do
    system "#{bin}/initdb", testpath/"test" unless ENV["HOMEBREW_GITHUB_ACTIONS"]
    assert_equal opt_pkgshare.to_s, shell_output("#{bin}/pg_config --sharedir").chomp
    assert_equal opt_lib.to_s, shell_output("#{bin}/pg_config --libdir").chomp
    assert_equal opt_lib.to_s, shell_output("#{bin}/pg_config --pkglibdir").chomp
  end
end

__END__
diff --git a/configure b/configure
index 90d57f9880..60b587fd30 100755
--- a/configure
+++ b/configure
@@ -12299,7 +12299,7 @@ done
   # defines OPENSSL_VERSION_NUMBER to claim version 2.0.0, even though it
   # doesn't have these OpenSSL 1.1.0 functions. So check for individual
   # functions.
-  for ac_func in OPENSSL_init_ssl BIO_get_data BIO_meth_new ASN1_STRING_get0_data RAND_OpenSSL
+  for ac_func in OPENSSL_init_ssl BIO_meth_new ASN1_STRING_get0_data RAND_OpenSSL
 do :
   as_ac_var=`$as_echo "ac_cv_func_$ac_func" | $as_tr_sh`
 ac_fn_c_check_func "$LINENO" "$ac_func" "$as_ac_var"
diff --git a/configure.in b/configure.in
index b092510077..64a3cd6902 100644
--- a/configure.in
+++ b/configure.in
@@ -1285,7 +1285,7 @@ if test "$with_openssl" = yes ; then
   # defines OPENSSL_VERSION_NUMBER to claim version 2.0.0, even though it
   # doesn't have these OpenSSL 1.1.0 functions. So check for individual
   # functions.
-  AC_CHECK_FUNCS([OPENSSL_init_ssl BIO_get_data BIO_meth_new ASN1_STRING_get0_data RAND_OpenSSL])
+  AC_CHECK_FUNCS([OPENSSL_init_ssl BIO_meth_new ASN1_STRING_get0_data RAND_OpenSSL])
   # OpenSSL versions before 1.1.0 required setting callback functions, for
   # thread-safety. In 1.1.0, it's no longer required, and CRYPTO_lock()
   # function was removed.
diff --git a/src/backend/libpq/be-secure-openssl.c b/src/backend/libpq/be-secure-openssl.c
index e307bfea82..255f5d61b7 100644
--- a/src/backend/libpq/be-secure-openssl.c
+++ b/src/backend/libpq/be-secure-openssl.c
@@ -663,11 +663,6 @@ be_tls_write(Port *port, void *ptr, size_t len, int *waitfor)
  * to retry; do we need to adopt their logic for that?
  */

-#ifndef HAVE_BIO_GET_DATA
-#define BIO_get_data(bio) (bio->ptr)
-#define BIO_set_data(bio, data) (bio->ptr = data)
-#endif
-
 static BIO_METHOD *my_bio_methods = NULL;

 static int
@@ -677,7 +672,7 @@ my_sock_read(BIO *h, char *buf, int size)

 	if (buf != NULL)
 	{
-		res = secure_raw_read(((Port *) BIO_get_data(h)), buf, size);
+		res = secure_raw_read(((Port *) BIO_get_app_data(h)), buf, size);
 		BIO_clear_retry_flags(h);
 		if (res <= 0)
 		{
@@ -697,7 +692,7 @@ my_sock_write(BIO *h, const char *buf, int size)
 {
 	int			res = 0;

-	res = secure_raw_write(((Port *) BIO_get_data(h)), buf, size);
+	res = secure_raw_write(((Port *) BIO_get_app_data(h)), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res <= 0)
 	{
@@ -773,7 +768,7 @@ my_SSL_set_fd(Port *port, int fd)
 		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
 		goto err;
 	}
-	BIO_set_data(bio, port);
+	BIO_set_app_data(bio, port);

 	BIO_set_fd(bio, fd, BIO_NOCLOSE);
 	SSL_set_bio(port->ssl, bio, bio);
diff --git a/src/include/pg_config.h.in b/src/include/pg_config.h.in
index 157b504ea6..d4c9b29aeb 100644
--- a/src/include/pg_config.h.in
+++ b/src/include/pg_config.h.in
@@ -96,9 +96,6 @@
 /* Define to 1 if you have the <atomic.h> header file. */
 #undef HAVE_ATOMIC_H

-/* Define to 1 if you have the `BIO_get_data' function. */
-#undef HAVE_BIO_GET_DATA
-
 /* Define to 1 if you have the `BIO_meth_new' function. */
 #undef HAVE_BIO_METH_NEW

diff --git a/src/include/pg_config.h.win32 b/src/include/pg_config.h.win32
index d2149996d2..4e74324079 100644
--- a/src/include/pg_config.h.win32
+++ b/src/include/pg_config.h.win32
@@ -75,9 +75,6 @@
 /* Define to 1 if you have the `ASN1_STRING_get0_data' function. */
 /* #undef HAVE_ASN1_STRING_GET0_DATA */

-/* Define to 1 if you have the `BIO_get_data' function. */
-/* #undef HAVE_BIO_GET_DATA */
-
 /* Define to 1 if you have the `BIO_meth_new' function. */
 /* #undef HAVE_BIO_METH_NEW */

diff --git a/src/interfaces/libpq/fe-secure-openssl.c b/src/interfaces/libpq/fe-secure-openssl.c
index 55e231e849..bf091c0ec5 100644
--- a/src/interfaces/libpq/fe-secure-openssl.c
+++ b/src/interfaces/libpq/fe-secure-openssl.c
@@ -1491,11 +1491,6 @@ PQsslAttribute(PGconn *conn, const char *attribute_name)
  * to retry; do we need to adopt their logic for that?
  */

-#ifndef HAVE_BIO_GET_DATA
-#define BIO_get_data(bio) (bio->ptr)
-#define BIO_set_data(bio, data) (bio->ptr = data)
-#endif
-
 static BIO_METHOD *my_bio_methods;

 static int
@@ -1503,7 +1498,7 @@ my_sock_read(BIO *h, char *buf, int size)
 {
 	int			res;

-	res = pqsecure_raw_read((PGconn *) BIO_get_data(h), buf, size);
+	res = pqsecure_raw_read((PGconn *) BIO_get_app_data(h), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res < 0)
 	{
@@ -1533,7 +1528,7 @@ my_sock_write(BIO *h, const char *buf, int size)
 {
 	int			res;

-	res = pqsecure_raw_write((PGconn *) BIO_get_data(h), buf, size);
+	res = pqsecure_raw_write((PGconn *) BIO_get_app_data(h), buf, size);
 	BIO_clear_retry_flags(h);
 	if (res <= 0)
 	{
@@ -1624,7 +1619,7 @@ my_SSL_set_fd(PGconn *conn, int fd)
 		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
 		goto err;
 	}
-	BIO_set_data(bio, conn);
+	BIO_set_app_data(bio, conn);

 	SSL_set_bio(conn->ssl, bio, bio);
 	BIO_set_fd(bio, fd, BIO_NOCLOSE);
diff --git a/src/tools/msvc/Solution.pm b/src/tools/msvc/Solution.pm
index c823655ed9..f88609ebc8 100644
--- a/src/tools/msvc/Solution.pm
+++ b/src/tools/msvc/Solution.pm
@@ -277,7 +277,6 @@ sub GenerateFiles
 				|| ($digit1 >= '1' && $digit2 >= '1' && $digit3 >= '0'))
 			{
 				print $o "#define HAVE_ASN1_STRING_GET0_DATA 1\n";
-				print $o "#define HAVE_BIO_GET_DATA 1\n";
 				print $o "#define HAVE_BIO_METH_NEW 1\n";
 				print $o "#define HAVE_OPENSSL_INIT_SSL 1\n";
 			}
