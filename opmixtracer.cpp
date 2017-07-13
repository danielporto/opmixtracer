
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>

/*
//Helpers
*/

/*
* accurate time, results in nanosseconds
*/

//new c++11 std
//#include <chrono>
//using namespace std::chrono;
// long long get_timestamp{
//   high_resolution_clock::time_point t1 = high_resolution_clock::now();
//   high_resolution_clock::duration dt1 = t1.time_since_epoch();
//   return dt1.count();
// }

#include <ctime>
long get_timestamp()
{ 
    struct timeval tv;
    gettimeofday(&tv,NULL);
    //tv.tv_sec // seconds
    //tv.tv_usec // microseconds
    long timestamp = tv.tv_sec*1000000L +tv.tv_usec;
    //std::cout << " c standard: " <<large <<std::endl;
    return timestamp;
}


/* ================================================================== */
// Global variables 
/* ================================================================== */
const UINT32 MAX_INSTRUCTIONS=1530; //3 byte lenght opcodes
UINT64 STATS[MAX_INSTRUCTIONS];
PIN_LOCK lockStats;
PIN_LOCK lockTimeInterval;
PIN_LOCK lockTotalInstuctions;

UINT64 insInterval = 0;
UINT64 totalInstuctions=0;
UINT64 timeInterval = 0;
UINT64 lastTimeInterval = 0;

std::ofstream *out = 0;
/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "opmixtrace.out", "specify file prefix for Opmixtrace output");

//the operation checkpoint determine the number of operations required to check
//wheter it is time to checkpoint.
KNOB<INT32>   KnobOperationThreshold(KNOB_MODE_WRITEONCE,  "pintool",
    "operations", "1000000", "checkpoint for checking the time interval to count instructions, basic blocks and threads in the application");

//the time for checkpoiting is defined ms
KNOB<INT32>   KnobTimeThreshold(KNOB_MODE_WRITEONCE,  "pintool",
    "time", "1000000", "time interval to write down the trace into the output file");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */

VOID PrintCSVHeader(ofstream& out)
{
    out <<"!Timestamp;";
    for ( UINT32 i = 0; i < MAX_INSTRUCTIONS; i++)
    {
        out <<OPCODE_StringShort(i) << ";";
    }   
    out << endl;
    out.flush();
}

VOID Print(ofstream& out, const string& text)
{
    out <<"! " << text << endl;
    out.flush();
}

VOID PrintStatsToCSV(ofstream& out, UINT64 timestamp)
{
    out << timestamp <<";";
    for ( UINT32 i = 0; i < MAX_INSTRUCTIONS; i++)
    {
        out <<STATS[i] << ";";
    }   
    out << endl;
    out.flush();
}

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID docount(UINT64 * counter)
{
    PIN_GetLock(&lockStats,0);
    (*counter)++;
    PIN_ReleaseLock(&lockStats);
    totalInstuctions++;
    if (totalInstuctions % insInterval == 0 )
    {
        // static stringstream ss;
        // ss << "timestamp " << lastTimeInterval << ";" <<endl;
        // Print(*out,ss.str());
        UINT64 now = get_timestamp();
        if ( now - lastTimeInterval >= timeInterval)  
        {
            lastTimeInterval=now;
            PrintStatsToCSV(*out, now);
        }

    }
}
/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the docount() analysis routine before every instruction 
 * of the trace.
 * @param[in]   ins    instruction found
 * @param[in]   v      value specified by the tool in the Instruction function call
 */
VOID Instruction(INS ins, VOID *v)
{
    //this is not optimal but will do the job
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(STATS[INS_Opcode(ins)]), IARG_END);
}




VOID Fini(INT32 code, VOID *v)
{
    UINT64 now = get_timestamp();
    PrintStatsToCSV(*out,now);
    *out <<  "!===============================================" << endl;
    *out <<  "!OpMixTracer total instructions: " << totalInstuctions << endl;
    *out <<  "!===============================================" << endl;
    out->close();
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    //Initialize all locks
    PIN_InitLock(&lockStats);
    PIN_InitLock(&lockTimeInterval);
    PIN_InitLock(&lockTotalInstuctions);

    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string fileName = KnobOutputFile.Value();
    insInterval = KnobOperationThreshold.Value();
    timeInterval = KnobTimeThreshold.Value();
    lastTimeInterval = get_timestamp();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    // Register function to be called to instrument traces
    INS_AddInstrumentFunction(Instruction, 0);
    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by OpMixTracer" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PrintCSVHeader(*out);
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
