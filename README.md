# Hydra 0.1.8

[Hydra](http://hydra.hellug.gr/) is a lightweight, multithreaded HTTP(S) server based on [Boa](https://github.com/shrug-security/boa-0.94.13) which is occasionally still found in embedded firmware images for serving CGI scripts, files, and more. 0.1.8 is the last stable version, and was released [in 2006](http://hydra.hellug.gr/download/).

### Known Vulnerabilities

- [CVE-2019-17502](https://www.cvedetails.com/cve/CVE-2019-17502/) - Discovered by [Felix Blanco](https://github.com/fxb6476): Hydra through 0.1.8 has a NULL pointer dereference & daemon crash when processing POST requests that lack a 'Content-Length' header. Links: [disclosure](https://gist.github.com/fxb6476/0b9883a88ff2ca40de46a8469834e16c).

### Changelog

* **Cleaning up**: [PR #1](https://github.com/shrug-security/hydra-0.1.8/pull/1) adds CI to build Hydra on every pull or PR.
* **Cleaning up**: [PR #2](https://github.com/shrug-security/hydra-0.1.8/pull/2) adds `clang-format` configuration and reformats all files to follow.

### Warranty & Liability

This work is licensed under the GNU GPLv2. This includes modifications by the SHRuG working group. In particular, we'd like to remind you of the "NO WARRANTY" section, as follows:

11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.