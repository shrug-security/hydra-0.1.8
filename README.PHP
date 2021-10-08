How to use Hydra with PHP. This is HIGHLY EXPERIMENTAL since there
are several known bugs, with the hydra sapi module.

0. Get PHP4.

1. Get hydra-sapi-0.y.x.tar.gz from ftp://ftp.hellug.gr/pub/software/hydra/php
   (note that 'y' and 'x' must match your Hydra version).

2. Untar the hydra-sapi tarball as a subdirectory called hydra/ in the sapi/
directory in the PHP main source tree.

3. CD into the PHP's source tree and run "autoconf"
   If you don't have autoconf, get it at ftp://ftp.gnu.org/

4. Proceed to "./configure --with-hydra=/where/hydra/source/is" and "make"
   Note that you should point to the root of the untarred data, not
   to the src/ directory.

5. Compile Hydra with SMP and HIC enabled (this is the default)

6. Edit the hydra.conf to enable HIC modules, and set the path of libphp4.so.

7. Run Hydra.
