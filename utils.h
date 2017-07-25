#ifndef __UTILS__
#define __UTILS__
#include <ctime>
static long get_timestamp()
{ 
    struct timeval tv;
    gettimeofday(&tv,NULL);
    //tv.tv_sec // seconds
    //tv.tv_usec // microseconds
    long timestamp = tv.tv_sec*1000000L +tv.tv_usec;
    //std::cout << " c standard: " <<timestamp <<std::endl;
    return timestamp;
}
#endif