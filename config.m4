dnl
dnl $Id$
dnl 

RESULT=no
PHP_ARG_WITH(onion,,
[  --with-onion[=DIR]      Build the onion server SAPI.
                          DIR is the prefix for onion installation [/usr]], no, no)

AC_MSG_CHECKING([for onion support])

if test "$PHP_ONION" != "no"; then
  if test ! -d $PHP_ONION ; then
    PHP_ONION=$prefix
  fi
  
  if test -f $PHP_ONION/include/onion/onion.h; then
    ONION_LIBPATH=$PHP_ONION/lib/
    ONION_INCLUDE=$PHP_ONION/include/onion
  else
    AC_MSG_ERROR([Could not locate onion at $PHP_ONION])
  fi
  
  AC_DEFINE(HAVE_ONION,1,[Whether to compile the onion server])
  
  PHP_ONION_CFLAGS="-DGNU_SOURCE -I$ONION_INCLUDE"
  PHP_ONION_FILES="onion.c"
  PHP_ONION_LIBS="-lpthread -lonion -lonion_handlers"
  
  PHP_SUBST(PHP_ONION_CFLAGS)
  PHP_SUBST(PHP_ONION_FILES)
  PHP_SUBST(PHP_ONION_LIBS)
  
  PHP_ADD_MAKEFILE_FRAGMENT([$abs_srcdir/sapi/onion/Makefile.frag])
  
  PHP_ADD_INCLUDE(ONION_INCLUDE)
  PHP_SELECT_SAPI(onion, program, "onion.c", $PHP_ONION_CFLAGS, [$(SAPI_ONION_PATH)])
  
  BUILD_BINARY_ONION="sapi/onion/php-onion"
  BUILD_ONION="\$(LIBTOOL) --mode=link \
        \$(CC) -export-dynamic \$(CFLAGS_CLEAN) \$(EXTRA_CFLAGS) \$(PHP_ONION_CFLAGS) \$(EXTRA_LDFLAGS_PROGRAM) \$(LDFLAGS) \$(PHP_RPATHS) \
                \$(PHP_GLOBAL_OBJS) \
                \$(PHP_BINARY_OBJS) \
                \$(PHP_ONION_OBJS) \
                \$(EXTRA_LIBS) \
                \$(ZEND_EXTRA_LIBS) \
                \$(PHP_ONION_LIBS) \
         -o \$(BUILD_BINARY_ONION)"
  
  PHP_SUBST(BUILD_BINARY_ONION)
  PHP_SUBST(BUILD_ONION)
  PHP_BUILD_THREAD_SAFE
  
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

dnl ## Local Variables:
dnl ## tab-width: 4
dnl ## End:
