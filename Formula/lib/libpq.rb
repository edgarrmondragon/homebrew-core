class Libpq < Formula
  desc "Postgres C API library"
  homepage "https://www.postgresql.org/docs/current/libpq.html"
  url "https://ftp.postgresql.org/pub/source/v16.1/postgresql-16.1.tar.bz2"
  sha256 "ce3c4d85d19b0121fe0d3f8ef1fa601f71989e86f8a66f7dc3ad546dd5564fec"
  license "PostgreSQL"
  revision 1

  livecheck do
    url "https://ftp.postgresql.org/pub/source/"
    regex(%r{href=["']?v?(\d+(?:\.\d+)+)/?["' >]}i)
  end

  bottle do
    sha256 arm64_sonoma:   "49ad6314bad02cc469d16edb472898ac17d0d2d5bc4033391b3d0933db1ab5a3"
    sha256 arm64_ventura:  "d368cb57bb4f04df6f6ace665a11bc34a2fe9cc39b8d8c337de61b3f937148d0"
    sha256 arm64_monterey: "7c96fa78808730ababf21f2c8dd938c9d56b50ea1c6f2362695a3a73ed17d921"
    sha256 sonoma:         "2ac1c0e20d1e3974e81d7cdc9c6d24bbdcf6e050dd3a60e2ed89f15922f21c4e"
    sha256 ventura:        "2a43fdee20b343e1c437d8c8cabeb17e0a46ca28c9478ac94d0fca96ae11e5b4"
    sha256 monterey:       "a80489ca19e00aa6920a9f9e2e30b7378df089a11f8b1dcb86276a9756384255"
    sha256 x86_64_linux:   "4d099a83019b774f9884bbae34d3c84ac981035c349bcfab661afe879d389280"
  end

  keg_only "conflicts with postgres formula"

  depends_on "pkg-config" => :build
  depends_on "icu4c"
  # GSSAPI provided by Kerberos.framework crashes when forked.
  # See https://github.com/Homebrew/homebrew-core/issues/47494.
  depends_on "krb5"
  depends_on "openssl@3"

  uses_from_macos "zlib"

  on_linux do
    depends_on "readline"
  end

  # Fix compatibility with OpenSSL 3.2
  # Remove once merged
  # Ref https://www.postgresql.org/message-id/CX9SU44GH3P4.17X6ZZUJ5D40N%40neon.tech
  patch :DATA

  def install
    system "./configure", "--disable-debug",
                          "--prefix=#{prefix}",
                          "--with-gssapi",
                          "--with-openssl",
                          "--libdir=#{opt_lib}",
                          "--includedir=#{opt_include}"
    dirs = %W[
      libdir=#{lib}
      includedir=#{include}
      pkgincludedir=#{include}/postgresql
      includedir_server=#{include}/postgresql/server
      includedir_internal=#{include}/postgresql/internal
    ]
    system "make"
    system "make", "-C", "src/bin", "install", *dirs
    system "make", "-C", "src/include", "install", *dirs
    system "make", "-C", "src/interfaces", "install", *dirs
    system "make", "-C", "src/common", "install", *dirs
    system "make", "-C", "src/port", "install", *dirs
    system "make", "-C", "doc", "install", *dirs
  end

  test do
    (testpath/"libpq.c").write <<~EOS
      #include <stdlib.h>
      #include <stdio.h>
      #include <libpq-fe.h>

      int main()
      {
          const char *conninfo;
          PGconn     *conn;

          conninfo = "dbname = postgres";

          conn = PQconnectdb(conninfo);

          if (PQstatus(conn) != CONNECTION_OK) // This should always fail
          {
              printf("Connection to database attempted and failed");
              PQfinish(conn);
              exit(0);
          }

          return 0;
        }
    EOS
    system ENV.cc, "libpq.c", "-L#{lib}", "-I#{include}", "-lpq", "-o", "libpqtest"
    assert_equal "Connection to database attempted and failed", shell_output("./libpqtest")
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
