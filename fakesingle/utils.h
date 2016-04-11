/* From service-launcher */

#ifndef _UTILS_H
#define _UTILS_H

#include <err.h>


#ifdef DEBUG
#define DEBUG_LINE " (at line %d in %s)", __LINE__, __FILE__
#define DBG_PRINT(args...) fprintf(stderr, args)
#else
#define DEBUG_LINE
#define DBG_PRINT(args...)
#endif

#define VERIFY(func, args...) do { if(func(args) < 0) err(-1, "unable to call " #func DEBUG_LINE); } while (0);
#define VERIFY_EXP(expression) do { if (!(expression)) err(-1, "unable to verify " #expression DEBUG_LINE); } while (0);
#define VERIFY_ASSN(ret, func, args...) do { if( (ret = func(args)) < 0) err(-1, "unable to call " #func DEBUG_LINE); } while (0);

#endif
