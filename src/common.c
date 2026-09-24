/*
 * This file use to handle printing log message
 */

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "common.h"

static void vlog(FILE *stream, const char *level, const char *fmt, va_list ap) {
	time_t now = time(NULL);	// get current time
	struct tm tmv;
	char stamp[32];

	localtime_r(&now, &tmv);	// convert current time to local time
	strftime(stamp, sizeof(stamp), "%H:%M:%S", &tmv);	// stamp keep time format hours:minutes:seconds
	fprintf(stream, "[%s] %s ", stamp, level);
	vfprintf(stream, fmt, ap);	// printing log message
	fputc('\n', stream);
}

void log_info(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vlog(stdout, "INFO", fmt, ap);
	va_end(ap);
}

void log_error(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vlog(stderr, "ERROR", fmt, ap);
	va_end(ap);
}
