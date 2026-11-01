/* The import the MIPS fixtures call: a shared library of its own for the
 * position-independent one, linked in whole for the other. */
int puts(const char *s) { return s[0]; }
