dnl Exports one of ac_cv_func_poll or ac_cv_func_select
AC_DEFUN([POLL_OR_SELECT],
  [
    AC_MSG_CHECKING(whether to use poll or select)
    AC_ARG_WITH(select,
    [  --with-select           Use select instead of poll],
    [
      if test "$withval" = "yes" ; then
        AC_MSG_RESULT(trying select)
        ac_x=1
      else
        AC_MSG_RESULT(trying poll)
        ac_x=0
      fi
    ],
    [
      AC_MSG_RESULT(trying poll)
      ac_x=0
    ])

    if test $ac_x = 0; then
      AC_CHECK_HEADERS(sys/poll.h)
      AC_CHECK_FUNCS(poll)
      if test "x$ac_cv_func_poll" = "x"; then
        AC_MSG_ERROR(We attempted to find poll but could not. Please try again with --with-select)
      fi
      BOA_ASYNC_IO="poll"
    else
      AC_CHECK_HEADERS(sys/select.h)
      AC_CHECK_FUNCS(select)
      if test "x$ac_cv_func_select" = "x"; then
        AC_MSG_ERROR(We attempted to find select but could not. Please try again with --without-select)
      fi
      BOA_ASYNC_IO="select"
    fi
  ]
)

