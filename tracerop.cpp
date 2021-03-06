/*! @file
 *  This file contains a static and dynamic opcode  mix profiler
 */

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include "pin.H"

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,         "pintool",
    "o", "tracerop.out", "specify profile file name");
KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE,                "pintool",
    "i", "0", "append pid to output");
KNOB<BOOL>   KnobProfilePredicated(KNOB_MODE_WRITEONCE,  "pintool",
    "p", "0", "enable accurate profiling for predicated instructions");
KNOB<BOOL>   KnobNoSharedLibs(KNOB_MODE_WRITEONCE,       "pintool",
    "no_shared_libs", "0", "do not instrument shared libraries");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This pin tool computes a static and dynamic opcode mix profile\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */
/* INDEX HELPERS */
/* ===================================================================== */

const UINT32 MAX_INDEX = 4096;
const UINT32 INDEX_SPECIAL =  3000;
const UINT32 MAX_MEM_SIZE = 512;


const UINT32 INDEX_TOTAL =          INDEX_SPECIAL + 0;
const UINT32 INDEX_MEM_ATOMIC =     INDEX_SPECIAL + 1;
const UINT32 INDEX_STACK_READ =     INDEX_SPECIAL + 2;
const UINT32 INDEX_STACK_WRITE =    INDEX_SPECIAL + 3;
const UINT32 INDEX_IPREL_READ =     INDEX_SPECIAL + 4;
const UINT32 INDEX_IPREL_WRITE =    INDEX_SPECIAL + 5;
const UINT32 INDEX_MEM_READ_SIZE =  INDEX_SPECIAL + 6;
const UINT32 INDEX_MEM_WRITE_SIZE = INDEX_SPECIAL + 6 + MAX_MEM_SIZE;
const UINT32 INDEX_SPECIAL_END   =  INDEX_SPECIAL + 6 + MAX_MEM_SIZE + MAX_MEM_SIZE;


BOOL IsMemReadIndex(UINT32 i)
{
    return (INDEX_MEM_READ_SIZE <= i && i < INDEX_MEM_READ_SIZE + MAX_MEM_SIZE );
}

BOOL IsMemWriteIndex(UINT32 i)
{
    return (INDEX_MEM_WRITE_SIZE <= i && i < INDEX_MEM_WRITE_SIZE + MAX_MEM_SIZE );
}


/* ===================================================================== */

LOCALFUN UINT32 INS_GetIndex(INS ins)
{
    if( INS_IsPredicated(ins) )
        return MAX_INDEX + INS_Opcode(ins);
    else
        return INS_Opcode(ins);
}

/* ===================================================================== */

//count how many instructions are in the block
LOCALFUN  UINT32 IndexStringLength(BBL bbl, BOOL memory_acess_profile)
{
    UINT32 count = 0;

    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
    {
        count++;
        if( memory_acess_profile )
        {
            if( INS_IsMemoryRead(ins) ) count++;   // for size

            if( INS_IsStackRead(ins) ) count++;

            if( INS_IsIpRelRead(ins) ) count++;


            if( INS_IsMemoryWrite(ins) ) count++; // for size

            if( INS_IsStackWrite(ins) ) count++;

            if( INS_IsIpRelWrite(ins) ) count++;


            if( INS_IsAtomicUpdate(ins) ) count++;
        }
    }

    return count;
}


/* ===================================================================== */
LOCALFUN UINT32 MemsizeToIndex(UINT32 size, BOOL write)
{
    return (write ? INDEX_MEM_WRITE_SIZE : INDEX_MEM_READ_SIZE ) + size;
}

/* ===================================================================== */
LOCALFUN UINT16 *INS_GenerateIndexString(INS ins, UINT16 *stats, BOOL memory_acess_profile)
{
    *stats++ = INS_GetIndex(ins);

    if( memory_acess_profile )
    {
        if( INS_IsMemoryRead(ins) )  *stats++ = MemsizeToIndex( INS_MemoryReadSize(ins), 0 );
        if( INS_IsMemoryWrite(ins) ) *stats++ = MemsizeToIndex( INS_MemoryWriteSize(ins), 1 );

        if( INS_IsAtomicUpdate(ins) ) *stats++ = INDEX_MEM_ATOMIC;

        if( INS_IsStackRead(ins) ) *stats++ = INDEX_STACK_READ;
        if( INS_IsStackWrite(ins) ) *stats++ = INDEX_STACK_WRITE;

        if( INS_IsIpRelRead(ins) ) *stats++ = INDEX_IPREL_READ;
        if( INS_IsIpRelWrite(ins) ) *stats++ = INDEX_IPREL_WRITE;
    }

    return stats;
}


/* ===================================================================== */

LOCALFUN string IndexToOpcodeString( UINT32 index )
{
    if( INDEX_SPECIAL <= index  && index < INDEX_SPECIAL_END)
    {
        if( index == INDEX_TOTAL )            return  "*total";
        else if( IsMemReadIndex(index) )      return  "*mem-read-" + decstr( index - INDEX_MEM_READ_SIZE );
        else if( IsMemWriteIndex(index))      return  "*mem-write-" + decstr( index - INDEX_MEM_WRITE_SIZE );
        else if( index == INDEX_MEM_ATOMIC )  return  "*mem-atomic";
        else if( index == INDEX_STACK_READ )  return  "*stack-read";
        else if( index == INDEX_STACK_WRITE ) return  "*stack-write";
        else if( index == INDEX_IPREL_READ )  return  "*iprel-read";
        else if( index == INDEX_IPREL_WRITE ) return  "*iprel-write";

        else
        {
            ASSERTX(0);
            return "";
        }
    }
    else
    {
        return OPCODE_StringShort(index);
    }

}

/* ===================================================================== */
/* ===================================================================== */
typedef UINT64 COUNTER;


/* zero initialized */

class STATS
{
  public:
    COUNTER unpredicated[MAX_INDEX];
    COUNTER predicated[MAX_INDEX];
    COUNTER predicated_true[MAX_INDEX];

    VOID Clear()
    {
        for ( UINT32 i = 0; i < MAX_INDEX; i++)
        {
            unpredicated[i] = 0;
            predicated[i] = 0;
            predicated_true[i] = 0;
        }
    }
};


STATS GlobalStatsStatic;
STATS GlobalStatsDynamic;

class BBLSTATS
{
  public:
    COUNTER _counter;
    const UINT16 * const _stats;

  public:
    BBLSTATS(UINT16 * stats) : _counter(0), _stats(stats) {};

};


// key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key = INVALID_TLS_KEY;
INT32 numThreads = 0;
static std::ofstream* out = 0;
const UINT32 MAX_THREADS = 100;
LOCALVAR vector<const BBLSTATS*> statsList[MAX_THREADS];

/* ===================================================================== */

VOID PIN_FAST_ANALYSIS_CALL docount(COUNTER * counter, THREADID threadid)
{
    (*counter) += 1;
}
/*=======================================================================*/
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    numThreads++;
}
// This function is called when the thread exits
VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    *out << "Count[" << decstr(threadIndex) << "] = finished" << endl;
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
    if ( KnobNoSharedLibs.Value()
         && IMG_Type(SEC_Img(RTN_Sec(TRACE_Rtn(trace)))) == IMG_TYPE_SHAREDLIB)
        return;

    const BOOL accurate_handling_of_predicates = KnobProfilePredicated.Value();

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        const INS head = BBL_InsHead(bbl);
        if (! INS_Valid(head)) continue;

        // Summarize the stats for the bbl in a 0 terminated list
        // This is done at instrumentation time
        const UINT32 n = IndexStringLength(bbl, 1);

        UINT16 *const stats = new UINT16[ n + 1];
        UINT16 *const stats_end = stats + (n + 1);
        UINT16 *curr = stats;

        for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins))
        {
            // Count the number of times a predicated instruction is actually executed
            // this is expensive and hence disabled by default
            if( INS_IsPredicated(ins) && accurate_handling_of_predicates )
            {
                INS_InsertPredicatedCall(ins,
                                         IPOINT_BEFORE,
                                         AFUNPTR(docount),
                                         IARG_PTR, &(GlobalStatsDynamic.predicated_true[INS_Opcode(ins)]),
                                         IARG_THREAD_ID,
                                         IARG_END);
            }

            curr = INS_GenerateIndexString(ins,curr,1);
        }

        // string terminator
        *curr++ = 0;

        ASSERTX( curr == stats_end );


        // Insert instrumentation to count the number of times the bbl is executed
        BBLSTATS * bblstats = new BBLSTATS(stats);
        INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(bblstats->_counter), IARG_THREAD_ID, IARG_END);

        // Remember the counter and stats so we can compute a summary at the end
        statsList[PIN_ThreadId()].push_back(bblstats);
    }
}

/* ===================================================================== */
VOID DumpStats(ofstream& out, STATS& stats, BOOL predicated_true,  const string& title)
{
    out <<
        "#\n"
        "# " << title << "\n"
        "#\n"
        "#     opcode       count-unpredicated    count-predicated";

    if( predicated_true )
        out << "    count-predicated-true";

    out << "\n#\n";

    for ( UINT32 i = 0; i < INDEX_TOTAL; i++)
    {
        stats.unpredicated[INDEX_TOTAL] += stats.unpredicated[i];
        stats.predicated[INDEX_TOTAL] += stats.predicated[i];
        stats.predicated_true[INDEX_TOTAL] += stats.predicated_true[i];
    }

    for ( UINT32 i = 0; i < MAX_INDEX; i++)
    {
        if( stats.unpredicated[i] == 0 &&
            stats.predicated[i] == 0 ) continue;

        out << setw(4) << i << " " <<  ljstr(IndexToOpcodeString(i),15) << " " <<
            setw(16) << stats.unpredicated[i] << " " <<
            setw(16) << stats.predicated[i];
        if( predicated_true ) out << " " << setw(16) << stats.predicated_true[i];
        out << endl;
    }
}



/* ===================================================================== */

VOID Fini(int, VOID * v)
{

    // static counts

    DumpStats(*out, GlobalStatsStatic, false, "$static-counts");

    *out << endl;

    // dynamic Counts

    for(UINT32 i=0; i< MAX_THREADS; i++) 
        statsList[i].push_back(0); // add terminator marker

    for(UINT32 i=0; i< MAX_THREADS; i++) 
    for (vector<const BBLSTATS*>::iterator bi = statsList[i].begin(); bi != statsList[i].end(); bi++)
    {
        const BBLSTATS *b = (*bi);

        if ( b == 0 ) continue;

        for (const UINT16 * stats = b->_stats; *stats; stats++)
        {
            GlobalStatsDynamic.unpredicated[*stats] += b->_counter;
        }
    }


    DumpStats(*out, GlobalStatsDynamic, KnobProfilePredicated, "$dynamic-counts");

    *out << "# $eof" <<  endl;

    out->close();
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    //control.RegisterHandler(Handler, 0, FALSE);
    //control.Activate();

    string filename =  KnobOutputFile.Value();

    if (KnobPid)
    {
        filename += "." + decstr(getpid());
    }
    out = new std::ofstream(filename.c_str());

 // Obtain  a key for TLS storage.
    tls_key = PIN_CreateThreadDataKey(NULL);
    if (tls_key == INVALID_TLS_KEY)
    {
        cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << endl;
        PIN_ExitProcess(1);
    }
    // Register ThreadStart to be called when a thread starts.
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    // Register Fini to be called when thread exits.
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddFiniFunction(Fini, 0);


    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
