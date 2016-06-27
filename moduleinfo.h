#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "budp"


#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */

#define stringiz1(x) #x
#define stringize(x) stringiz1(x)

#ifndef BUILD_NUMBER
#define BUILD_NUMBER 0
#endif

#define VERSION "1.0." stringize(BUILD_NUMBER)

