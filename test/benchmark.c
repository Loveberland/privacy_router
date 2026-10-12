/*
 * check correctness and mesures the speed and memory usaged of domain filter
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "filter.h"

static double seconds(void)
{
	struct timespec time;
	assert(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
	return (double)time.tv_sec + (double)time.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	double started = seconds();
	assert(filter_load(argv[1]) == 0 && filter_count() == 100000);
	double load_seconds = seconds() - started;
	char queries[4096][64];
	for (unsigned int i = 0; i < 4096; ++i)
	{
		unsigned int domain = (i * 2654435761U) % 100000;
		if (i % 4 == 0)
		{
			snprintf(queries[i], sizeof(queries[i]), "allowed%u.other.test", domain);
		}
		else if (i % 4 == 1)
		{
			snprintf(queries[i], sizeof(queries[i]), "a.b.tracker%u.example.test", domain);
		}
		else
		{
			snprintf(queries[i], sizeof(queries[i]), "tracker%u.example.test", domain);
		}
	}

	started = seconds();
	size_t hits = 0;
	for (unsigned int i = 0; i < 2000000; ++i)
	{
		hits += (size_t)filter_blocked(queries[i % 4096]);
	}

	double lookup_seconds = seconds() - started;
	assert(hits == 1500000);
	struct rusage usage;
	assert(getrusage(RUSAGE_SELF, &usage) == 0);
	printf("{\"load_ms\":%.3f,\"lookup_ms\":%.3f,\"max_rss_kib\":%ld,\"hits\":%zu}\n", load_seconds * 1000, lookup_seconds * 1000, usage.ru_maxrss, hits);
	filter_free();

	return 0;
}