/*BEGIN_LEGAL 
 Intel Open Source License

 Copyright (c) 2002-2016 Intel Corporation. All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

 Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.  Redistributions
 in binary form must reproduce the above copyright notice, this list of
 conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.  Neither the name of
 the Intel Corporation nor the names of its contributors may be used to
 endorse or promote products derived from this software without
 specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
 ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 END_LEGAL */

/* ===================================================================== */
/*! @file This file contains a static and dynamic opcode/ISA extension/ISA
 *  category mix profiler
 *
 * This is derived from mix.cpp. Handles an arbitrary number of threads
 * using TLS for data storage and avoids locking, except during I/O.
 */

#if defined(TARGET_WINDOWS)
#define strdup _strdup
#endif

#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <unistd.h> //for getPid()
#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include "utils.h" //gettimestamp

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB_COMMENT tracer_knob_family("pintool:tracer", "Tracer knobs");

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool:tracer", "o",
		"fasttracer.out", "specify profile file name");
KNOB<BOOL> KnobPid(KNOB_MODE_WRITEONCE, "pintool:tracer", "i", "1",
		"append pid to output file name");
KNOB<BOOL> KnobProfilePredicated(KNOB_MODE_WRITEONCE, "pintool:tracer", "p",
		"0", "enable accurate profiling for predicated instructions");
KNOB<BOOL> KnobProfileStaticOnly(KNOB_MODE_WRITEONCE, "pintool:tracer", "s",
		"0", "terminate after collection of static profile for main image");
KNOB<BOOL> KnobProfileMemory(KNOB_MODE_WRITEONCE, "pintool:tracer", "m",
		"1", "terminate after collection of static profile for main image");
KNOB<BOOL> KnobNoSharedLibs(KNOB_MODE_WRITEONCE, "pintool:tracer",
		"no_shared_libs", "0", "do not instrument shared libraries");
KNOB<BOOL> KnobInstructionLengthTracer(KNOB_MODE_WRITEONCE, "pintool:tracer",
		"ilen", "0", "Compute instruction length tracer");
KNOB<BOOL> KnobCategoryTracer(KNOB_MODE_WRITEONCE, "pintool:tracer", "category",
		"0", "Compute ISA category tracer");
KNOB<BOOL> KnobExtensionTracer(KNOB_MODE_WRITEONCE, "pintool:tracer", "extension",
		"0", "Compute ISA category tracer");
KNOB<BOOL> KnobIformTracer(KNOB_MODE_WRITEONCE, "pintool:tracer", "iform", "0",
		"Compute ISA iform tracer");
#ifndef TARGET_WINDOWS
KNOB<BOOL> KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE, "pintool:tracer", "d",
		"0", "Only collect dynamic profile");
#else
KNOB<BOOL> KnobProfileDynamicOnly(KNOB_MODE_WRITEONCE,
		"pintool:tracer", "d", "1", "Only collect dynamic profile");
#endif
KNOB<UINT32> KnobTimer(KNOB_MODE_WRITEONCE, "pintool:tracer", "c", "1000",
		"specify the time interval");
KNOB<UINT32> KnobThreads(KNOB_MODE_WRITEONCE, "pintool:tracer", "t", "100",
		"specify the time interval");

/* ===================================================================== */

INT32 Usage() {
	cerr << "This pin tool computes a static and dynamic opcode, "
			<< "instruction form, instruction length, extension or category tracer profile\n\n";
	cerr << KNOB_BASE::StringKnobSummary();
	cerr << endl;
	cerr << "The default is to do opcode and ISA extension profiling" << endl;
	cerr << "At most one of -iform, -ilen or  -category is allowed" << endl;
	cerr << endl;
	return -1;
}

/* ===================================================================== */
/* INDEX HELPERS */
/* ===================================================================== */
typedef enum 
{
	INDEX_SPECIAL,
	INDEX_MEM_ATOMIC,
	INDEX_STACK_READ,
	INDEX_STACK_WRITE,
	INDEX_IPREL_READ,
	INDEX_IPREL_WRITE,
	INDEX_MEM_READ,
	INDEX_MEM_WRITE,
	INDEX_TOTAL,
	INDEX_SPECIAL_END
} index_t;

const UINT32 BUCKET_MAX_INSTRUCTION_CODES = 1527; // extras/xed-intel64/include/xed/xed-iclass-enum.h
const UINT32 BUCKET_MAX_CATEGORY_CODES = 80; // extras/xed-intel64/include/xed/xed-category-enum.h
const UINT32 BUCKET_MAX_LEN_CODES = 20; // experiment with ffmpeg resulted in max=12
const UINT32 BUCKET_MAX_IFORMS_CODES = 6031; //extras/xed-intel64/include/xed/xed-iform-enum.h
const UINT32 BUCKET_MAX_EXTENSION_CODES = 58; // extras/xed-intel64/include/xed/xed-extension-enum.h
/* ===================================================================== */
/*Types*/
/* ===================================================================== */

typedef enum 
{
	measure_opcode = 0,
	measure_category = 1,
	measure_ilen = 2,
	measure_iform = 3,
	measure_extension = 4
} measurement_t;

typedef UINT32 stat_index_t;

typedef UINT64 COUNTER;

#if defined(__GNUC__)
#  if defined(TARGET_MAC) || defined(TARGET_WINDOWS)
#    define ALIGN_LOCK __attribute__ ((aligned(16)))
#  else
#    define ALIGN_LOCK __attribute__ ((aligned(64)))
#  endif
#else
# define ALIGN_LOCK __declspec(align(64))
#endif

typedef struct 
{
	char pad0[64];
	PIN_LOCK ALIGN_LOCK lock; /* for mediating output */
	char pad1[64];
	PIN_LOCK ALIGN_LOCK bbl_list_lock; /* for the bbl list */
}ALIGN_LOCK locks_t;

/* ===================================================================== */

class DATACOUNTERS
{
	public:
		COUNTER *bucket;
		UINT32 base_size;
		UINT32 total_size;
		UINT32 index_total;

		DATACOUNTERS()
		{
			total_size=0;
			base_size=0;
			bucket = NULL;
			index_total=0;
		}

		DATACOUNTERS(measurement_t measure)
		{
			switch (measure) {
			case measure_opcode:
				base_size = BUCKET_MAX_INSTRUCTION_CODES;
				break;
			case measure_category:
				base_size = BUCKET_MAX_CATEGORY_CODES;
				break;
			case measure_ilen:
				base_size = BUCKET_MAX_LEN_CODES;
				break;
			case measure_iform:
				base_size = BUCKET_MAX_IFORMS_CODES;
				break;
			case measure_extension:
				base_size = BUCKET_MAX_EXTENSION_CODES;
				break;

			}
			total_size = base_size + INDEX_SPECIAL_END;
			index_total = base_size + INDEX_TOTAL;
			bucket = new COUNTER[total_size];
			clear();		
		}

		~DATACOUNTERS()
		{
			if(total_size>0){
				delete (bucket);
			}
		}

		VOID clear() {
			for (UINT32 i = 0; i < total_size; i++)
				bucket[i] = 0;
			bucket [base_size+INDEX_SPECIAL]=999999999999;
		}


};

class BBLSTATS 
{
	// Our first pass sets up the types of stats we need to update for this
	// block. We have one stat per instruction in the block. The _stats
	// array is null terminated.
	public:
		const stat_index_t* const _stats;
		const ADDRINT _pc; // start PC of the block
		const UINT32 _ninst; // # of instructions
		const UINT32 _nbytes; // # of bytes in the block
		BBLSTATS(stat_index_t* stats, ADDRINT pc, UINT32 ninst, UINT32 nbytes) :
				_stats(stats), _pc(pc), _ninst(ninst), _nbytes(nbytes) {
		};
};

class THREAD_DATA 
{
	public:
		DATACOUNTERS* datacounters;
		vector<COUNTER> block_counts;
		
		THREAD_DATA() 
		{
			datacounters=NULL;
		}
		
		UINT32 size() {
			UINT32 limit;
			limit = block_counts.size();
			return limit;
		}

		void resize(UINT32 n) {
			if (size() < n)
				block_counts.resize(2 * n);
		}
};

/* ===================================================================== */
/* Globals */
/* ===================================================================== */

locks_t locks;
measurement_t measurement = measure_opcode;
static TLS_KEY tls_key;
static std::ofstream* out;
DATACOUNTERS
 *GlobalStatsPredicated;  // only static analysis use both Globals
DATACOUNTERS
 *GlobalStatsUnpredicated;
LOCALVAR vector<BBLSTATS*> statsList;
THREADID printTraceThreadId;
UINT32 maxThreads;
UINT32 numThreads = 0;
UINT32 timeInterval;
THREAD_DATA* threadDataArray;
BOOL printThreadEnabled = true;

/* ===================================================================== */
/* index functions*/
/* ===================================================================== */
//

LOCALFUN UINT32 GetSpecialIndex()
{
	switch (measurement) {
			case measure_opcode: return BUCKET_MAX_INSTRUCTION_CODES;
			case measure_ilen: return BUCKET_MAX_LEN_CODES;
			case measure_category: return BUCKET_MAX_CATEGORY_CODES;
			case measure_extension: return BUCKET_MAX_EXTENSION_CODES;
			case measure_iform: return BUCKET_MAX_IFORMS_CODES;
	}
	return 0;
}

/* ===================================================================== */
LOCALFUN UINT32 INS_GetIndex(INS ins) 
{
	UINT32 index = 0;
	switch (measurement) {
		case measure_opcode:
			index = INS_Opcode(ins);
			break;
		case measure_ilen:
			index = INS_Size(ins);
			break;
		case measure_category:
			index = INS_Category(ins);
			break;
		case measure_extension:
			index = INS_Extension(ins);
			break;
		case measure_iform:
			xed_decoded_inst_t* xedd = INS_XedDec(ins);
			xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum(xedd);
			index = static_cast<UINT32>(iform);
			break;
	}
	return index;
}
/* ===================================================================== */

LOCALFUN UINT32 IndexStringLength(BBL bbl, BOOL memory_access_profile) 
{
	UINT32 count = 0;

	for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
		count++; // one for the ins

		if (memory_access_profile) {
			if (INS_IsAtomicUpdate(ins)) 	count++;
			if (INS_IsStackRead(ins))		count++;
			if (INS_IsStackWrite(ins))		count++;
			if (INS_IsIpRelRead(ins))		count++;
			if (INS_IsIpRelWrite(ins))		count++;
			if (INS_IsMemoryRead(ins))		count++;
			if (INS_IsMemoryWrite(ins))		count++;
		}
	}

	return count;
}


/* ===================================================================== */
LOCALFUN stat_index_t* INS_GenerateIndexString(INS ins, stat_index_t *stats,
		BOOL memory_access_profile) 
{
	*stats++ = INS_GetIndex(ins);

	if (memory_access_profile) {
		const UINT32 special_index = GetSpecialIndex();

		if (INS_IsAtomicUpdate(ins)) 	*stats++ = special_index + INDEX_MEM_ATOMIC;
		if (INS_IsStackRead(ins))	*stats++ = special_index +INDEX_STACK_READ;
		if (INS_IsStackWrite(ins))	*stats++ = special_index +INDEX_STACK_WRITE;
		if (INS_IsIpRelRead(ins))	*stats++ = special_index +INDEX_IPREL_READ;
		if (INS_IsIpRelWrite(ins))	*stats++ = special_index +INDEX_IPREL_WRITE;
		if (INS_IsMemoryRead(ins))	*stats++ = special_index + INDEX_MEM_READ;
		if (INS_IsMemoryWrite(ins))	*stats++ = special_index +INDEX_MEM_WRITE;
	}
	return stats;
}

/* ===================================================================== */

LOCALFUN string IndexToString(UINT32 index) 
{

	const UINT32 SPECIAL_INDEX = GetSpecialIndex();
	if ( index >= SPECIAL_INDEX ) {
		if (index == SPECIAL_INDEX )							return "*SPECIAL";
		else if (index == SPECIAL_INDEX + INDEX_MEM_ATOMIC)		return "*mem-atomic";
		else if (index == SPECIAL_INDEX + INDEX_STACK_READ)		return "*stack-read";
		else if (index == SPECIAL_INDEX + INDEX_STACK_WRITE)	return "*stack-write";
		else if (index == SPECIAL_INDEX + INDEX_IPREL_READ)		return "*iprel-read";
		else if (index == SPECIAL_INDEX + INDEX_IPREL_WRITE)	return "*iprel-write";
		else if (index == SPECIAL_INDEX + INDEX_MEM_READ)		return "*mem-read";
		else if (index == SPECIAL_INDEX + INDEX_MEM_WRITE)		return "*mem-write";
		else if (index == SPECIAL_INDEX + INDEX_TOTAL)			return "*total";
		else if (index == SPECIAL_INDEX + INDEX_SPECIAL_END)	return "*SPECIAL_END";
	}

	if (measurement == measure_opcode)		return OPCODE_StringShort(index);
	if (measurement ==  measure_category)	return CATEGORY_StringShort(index);
	if (measurement == measure_extension)	return EXTENSION_StringShort(index);
	if( measurement == measure_iform)		return xed_iform_enum_t2str(static_cast<xed_iform_enum_t>(index));
	if (measurement == measure_ilen){
		ostringstream s;
		s << "ILEN-" << index;
		return s.str();
	}
	return "IDX_PROBLEM";
}

/*========================================================================*/

LOCALFUN THREAD_DATA* get_tls(THREADID tid) 
{
	return &threadDataArray[tid];
}

/* ===================================================================== */

VOID UpdateLocalStats(THREADID tid)
{
	THREAD_DATA
* tdata = get_tls(tid);

	//get all discovered BBLs by this thread
	UINT32 discoveredBBLs = tdata->size();

	//statsList can be resized and addresses may change during this analysis
	//therefore, require a lock in here.
	PIN_GetLock(&locks.bbl_list_lock, tid + 2);

	/*Next: count the blocks that are already known by all other threads.
	* Thread block number can increase before the general (stats) list (look at the Trace method),
	* there, for every BBL, first the number of BBL is validated and increased if necessary
	* then, the BBLs are counted.
	* Thus, we need to **limit** the analysis to all known blocks so far.
	*/
	if ( discoveredBBLs  > statsList.size() )
		discoveredBBLs = statsList.size();

	for (UINT32 i = 0; i < discoveredBBLs; i++)
	{
		COUNTER bcount = tdata->block_counts[i];
		BBLSTATS* b = statsList[i];
		/* the last test below is for when new bbl's get jitted while we
		 * are emitting stats */

		if (b && b->_stats) //the string with the block DATACOUNTERS exists
			//recall that this string is formed by all opcodes
			//works like this: ADDMOVADDADDADD, for each time ADD is found in this
			//string, the number of times the block was executed is appended
			//to the array that maps all opcodes. this can be highly optmilized
			//later by pre-computing it.
			for (const stat_index_t* stats = b->_stats; *stats; stats++) {
				tdata->datacounters->bucket[*stats] += bcount;
			}
	}
	PIN_ReleaseLock(&locks.bbl_list_lock);
}

//TODO: Make this function compatible with accurate analysis
VOID updateGlobalStats() 
{
	THREAD_DATA* tdata;
	
	GlobalStatsUnpredicated->clear();

	for (UINT32 tid = 0; tid < numThreads; tid++) {
		tdata = get_tls(tid);

		PIN_GetLock(&locks.bbl_list_lock, tid + 2);
		UINT32 limit = tdata->size();
		if (limit > statsList.size())
			limit = statsList.size();

		for (UINT32 i = 0; i < limit; i++) {
			COUNTER bcount = tdata->block_counts[i];
			BBLSTATS* b = statsList[i];
			/* the last test below is for when new bbl's get jitted while we
			 * are emitting stats */
			if (b && b->_stats)
				for (const stat_index_t* stats = b->_stats; *stats; stats++) {
					GlobalStatsUnpredicated->bucket[*stats] += bcount;
					if (*stats <=  GlobalStatsUnpredicated->base_size)		
						GlobalStatsUnpredicated->bucket[GlobalStatsUnpredicated->index_total]+= bcount;
				}
		}
		PIN_ReleaseLock(&locks.bbl_list_lock);

	}
}

/* ===================================================================== */

/*
* To cope with the variable header size, we can print the header time to time
* and at the end of the experiment.
* this is important for the size of read/write memory fields
*/
//
VOID PrintCSVHeader(ofstream& out, DATACOUNTERS *stats)
{

	PIN_GetLock(&locks.lock, 0); // for output
	out << "!Timestamp;";
	for(UINT indx = 0; indx < stats->total_size; indx++){
		out << IndexToString(indx) << ";";
	}
	out <<endl;
	PIN_ReleaseLock(&locks.lock);

}

VOID PrintStatsToCSV(ofstream& out, UINT64 timestamp, DATACOUNTERS *stats,
		BOOL predicated_true) 
{

	PIN_GetLock(&locks.lock, 0); // for output
	out << timestamp <<";";
	for(UINT indx = 0; indx < stats->total_size; indx++){
		out << stats->bucket[indx]  << ";";
	}
	out << endl;
	PIN_ReleaseLock(&locks.lock);
}


/* ===================================================================== */
VOID printTraceThread(VOID * arg) 
{

	while (printThreadEnabled) {
		PIN_Sleep(timeInterval);
		updateGlobalStats();
		PrintStatsToCSV(*out, get_timestamp(), GlobalStatsUnpredicated,
				KnobProfilePredicated);

	}

}

/*=============================================================================*/
/* Analysis tools */
/*=============================================================================*/
VOID validate_bbl_count(THREADID tid, ADDRINT block_count_for_trace) 
{
	THREAD_DATA* tdata = get_tls(tid);
	tdata->resize(block_count_for_trace + 1);
}

VOID PIN_FAST_ANALYSIS_CALL docount_bbl(ADDRINT block_id, THREADID tid) 
{
	threadDataArray[tid].block_counts[block_id] += 1;
}

VOID docount_predicated_true(UINT32 index, THREADID tid) 
{
	THREAD_DATA* tdata = get_tls(tid);
	tdata->datacounters->bucket[index] += 1;
}
/*=============================================================================*/
/* Thread management specific functions */
/*=============================================================================*/

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) 
{
	// This function is locked no need for a Pin Lock here
	numThreads++;
	if (numThreads > maxThreads) {
		*out
				<< "Max thread number has been reached, aborting!! increase the number of threads!!"
				<< endl;
		exit(0);
	}
	PIN_GetLock(&locks.lock, tid + 2); // for output
	*out << "# Starting tid " << tid << endl;
	PIN_ReleaseLock(&locks.lock);

	// pre allocated in main, for fast access
	PIN_SetThreadData(tls_key, &threadDataArray[tid], tid);

}

// This function is called when the thread exits
VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v) 
{
	*out << "#Thread[" << decstr(tid) << "] = finished" << endl;

}
/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v) 
{
	static UINT32 basic_blocks = 0;

	if (KnobNoSharedLibs.Value()
			&& IMG_Type(SEC_Img(RTN_Sec(TRACE_Rtn(trace))))
					== IMG_TYPE_SHAREDLIB)
		return;

	const BOOL accurate_handling_of_predicates = KnobProfilePredicated.Value();
	const BOOL memory_access_profile = KnobProfileMemory.Value();

	ADDRINT pc = TRACE_Address(trace);

	UINT32 new_blocks = 0;
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		const INS head = BBL_InsHead(bbl);
		if (!INS_Valid(head))
			continue;
		new_blocks++;
	}

	TRACE_InsertCall(trace, IPOINT_BEFORE, AFUNPTR(validate_bbl_count),
			IARG_THREAD_ID, IARG_UINT32, basic_blocks + new_blocks,
			IARG_END);

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		const INS head = BBL_InsHead(bbl);
		if (!INS_Valid(head))
			continue;

		// Summarize the stats for the bbl in a 0 terminated list
		// This is done at instrumentation time
		const UINT32 n = IndexStringLength(bbl, memory_access_profile);

		ADDRINT block_start_pc = pc;

		// stats is an array of index types. We later multiply it by the
		// dynamic count for a block.
		stat_index_t * const stats = new stat_index_t[n + 1];
		stat_index_t * const stats_end = stats + (n + 1);
		stat_index_t *curr = stats;
		UINT32 ninsts = 0;
		for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins)) {
			UINT32 instruction_size = INS_Size(ins);
			// Count the number of times a predicated instruction is actually executed
			// this is expensive and hence disabled by default
			if (INS_IsPredicated(ins) && accurate_handling_of_predicates) {
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
						AFUNPTR(docount_predicated_true), IARG_UINT32,
						INS_GetIndex(ins), IARG_THREAD_ID,
						IARG_END);
			}

			curr = INS_GenerateIndexString(ins, curr, memory_access_profile);
			pc = pc + instruction_size;
			ninsts++;
		}

		// stats terminator
		*curr++ = 0;
		ASSERTX(curr == stats_end);

		// DEBUG - print bbl details
		// PIN_GetLock(&locks.lock, 0); // for output		
		// *out << "BBL:"<<block_start_pc << ";";
		// for(UINT32 a=0;a<n+1;a++){
		// 	*out<<curr[a] <<";";
		// }
		// *out << endl;
		// *out << "BBL:"<<block_start_pc << ";";
		// for(UINT32 a=0;a<n+1;a++){
		// 	*out<<IndexToString(curr[a]) <<";";
		// }
		// *out << endl;
		// PIN_ReleaseLock(&locks.lock);
		
		// Insert instrumentation to count the number of times the bbl is executed
		BBLSTATS * bblstats = new BBLSTATS(stats, block_start_pc, ninsts,
				pc - block_start_pc);
		INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(docount_bbl),
				IARG_FAST_ANALYSIS_CALL, IARG_UINT32, basic_blocks,
				IARG_THREAD_ID,
				IARG_END);

		// Remember the counter and stats so we can compute a summary at the end
		basic_blocks++;
		PIN_GetLock(&locks.bbl_list_lock, 1);
		statsList.push_back(bblstats);
		PIN_ReleaseLock(&locks.bbl_list_lock);
	}

}
/* ===================================================================== */

VOID Fini(int, VOID * v) // only runs once for the application
{
	printThreadEnabled = false;
	PIN_WaitForThreadTermination(printTraceThreadId, PIN_INFINITE_TIMEOUT,
			NULL);
	updateGlobalStats();
	PrintStatsToCSV(*out, get_timestamp(), GlobalStatsUnpredicated,
			KnobProfilePredicated);
	out->close();
}

/* ===================================================================== */
/* Static analysis */
/* ===================================================================== */

VOID Image(IMG img, VOID * v) 
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
			// Prepare for processing of RTN, an  RTN is not broken up into BBLs,
			// it is merely a sequence of INSs
			RTN_Open(rtn);

			for (INS ins = RTN_InsHead(rtn); INS_Valid(ins);
					ins = INS_Next(ins)) {
				stat_index_t array[256];
				stat_index_t* mid = INS_GenerateIndexString(ins, array, 1);
				stat_index_t* end = mid;

				if (INS_IsPredicated(ins)) {
					for (stat_index_t *start = array; start < end; start++) {
						GlobalStatsPredicated->bucket
				[*start]++;
					}
				} else {
					for (stat_index_t *start = array; start < end; start++) {
						GlobalStatsUnpredicated->bucket
				[*start]++;
					}
				}
			}

			// to preserve space, release data associated with RTN after we have processed it
			RTN_Close(rtn);
		}
	}

	if (KnobProfileStaticOnly.Value()) {
		Fini(0, 0);
		exit(0);
	}
}

/* ===================================================================== */

int main(int argc, CHAR **argv) 
{
	PIN_InitSymbols();
	if (PIN_Init(argc, argv))
		return Usage();

	//process command line parameters/knobs
	timeInterval = KnobTimer.Value();
	string filename = KnobOutputFile.Value();
	if (KnobPid) {
		filename += "." + decstr(getpid());
	}
	out = new std::ofstream(filename.c_str());

	// make sure that exactly one thing-to-count knob is specified.
	if (KnobInstructionLengthTracer.Value() && KnobCategoryTracer.Value()) {
		cerr << "Must have at most  one of: -iform, -ilen or -category "
				<< "as a pintool option" << endl;
		exit(1);
	}
	if (KnobInstructionLengthTracer.Value())
		measurement = measure_ilen;
	if (KnobCategoryTracer.Value())
		measurement = measure_category;
	if (KnobIformTracer.Value())
		measurement = measure_iform;
	if (KnobExtensionTracer.Value())
		measurement = measure_extension;

	maxThreads = KnobThreads.Value();
	threadDataArray = new THREAD_DATA[maxThreads];
	for(UINT32 i=0; i < maxThreads;i++){
		threadDataArray[i].datacounters = new DATACOUNTERS(measurement);

	}
	GlobalStatsPredicated = new DATACOUNTERS(measurement);
	GlobalStatsUnpredicated = new DATACOUNTERS(measurement);

	PIN_InitLock(&locks.lock);
	PIN_InitLock(&locks.bbl_list_lock);

	// obtain  a key for TLS storage
	tls_key = PIN_CreateThreadDataKey(0);


	TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, NULL);
	PIN_AddFiniFunction(Fini, 0);

	if (!KnobProfileDynamicOnly.Value())
		IMG_AddInstrumentFunction(Image, 0);

	PrintCSVHeader(*out,GlobalStatsUnpredicated);
	printTraceThreadId = PIN_SpawnInternalThread(printTraceThread, NULL, 0,
			NULL);
	ASSERT(printTraceThreadId != INVALID_THREADID,
			"Fail to spawn internal print thread");

	PIN_StartProgram();    // Never returns
	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
