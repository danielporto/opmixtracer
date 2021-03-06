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
#include <iomanip>
#include <fstream>
#include <utility> /* for pair */
#include <vector>
#include <unistd.h>
#include "pin.H"
#include <map>

extern "C" {
#include "xed-interface.h"
}
#include "utils.h"

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB_COMMENT tracer_knob_family("pintool:tracer", "Tracer knobs");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool:tracer", "o",
		"out.tracer", "specify profile file name");
KNOB<BOOL> KnobPid(KNOB_MODE_WRITEONCE, "pintool:tracer", "i", "1",
		"append pid to output file name");
KNOB<BOOL> KnobProfilePredicated(KNOB_MODE_WRITEONCE, "pintool:tracer", "p",
		"0", "enable accurate profiling for predicated instructions");
KNOB<BOOL> KnobProfileStaticOnly(KNOB_MODE_WRITEONCE, "pintool:tracer", "s",
		"0", "terminate after collection of static profile for main image");
KNOB<BOOL> KnobProfileMemory(KNOB_MODE_WRITEONCE, "pintool:tracer", "m",
		"0", "terminate after collection of static profile for main image");
KNOB<BOOL> KnobNoSharedLibs(KNOB_MODE_WRITEONCE, "pintool:tracer",
		"no_shared_libs", "0", "do not instrument shared libraries");
KNOB<BOOL> KnobInstructionLengthTracer(KNOB_MODE_WRITEONCE, "pintool:tracer",
		"ilen", "0", "Compute instruction length tracer");
KNOB<BOOL> KnobCategoryTracer(KNOB_MODE_WRITEONCE, "pintool:tracer", "category",
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

const UINT32 INDEX_SPECIAL = 3000;
const UINT32 MAX_MEM_SIZE = 520;
const UINT32 MAX_EXTENSION = XED_EXTENSION_LAST + 10;

const UINT32 INDEX_TOTAL = INDEX_SPECIAL + 0;
const UINT32 INDEX_MEM_ATOMIC = INDEX_SPECIAL + 1;
const UINT32 INDEX_STACK_READ = INDEX_SPECIAL + 2;
const UINT32 INDEX_STACK_WRITE = INDEX_SPECIAL + 3;
const UINT32 INDEX_IPREL_READ = INDEX_SPECIAL + 4;
const UINT32 INDEX_IPREL_WRITE = INDEX_SPECIAL + 5;
const UINT32 INDEX_MEM_READ_SIZE = INDEX_SPECIAL + 6;
const UINT32 INDEX_MEM_WRITE_SIZE = INDEX_SPECIAL + 6 + MAX_MEM_SIZE;

const UINT32 INDEX_EXTENSION = INDEX_SPECIAL + 6 + 2 * MAX_MEM_SIZE;

const UINT32 INDEX_SCALAR_SIMD = INDEX_EXTENSION + MAX_EXTENSION;
const UINT32 INDEX_FMA_BASE = INDEX_SCALAR_SIMD + 1;
const UINT32 INDEX_FMA = INDEX_FMA_BASE + 1;
const UINT32 INDEX_FMA_ADD = INDEX_FMA_BASE + 2;
const UINT32 INDEX_FMA_MUL = INDEX_FMA_BASE + 3;
const UINT32 INDEX_FMA_S = INDEX_FMA_BASE + 4;
const UINT32 INDEX_FMA_S_ADD = INDEX_FMA_BASE + 5; // NOTE: skipped 6. does not matter
const UINT32 INDEX_FMA_S_MUL = INDEX_FMA_BASE + 7;
const UINT32 INDEX_FMA_D = INDEX_FMA_BASE + 8;
const UINT32 INDEX_FMA_D_ADD = INDEX_FMA_BASE + 9;
const UINT32 INDEX_FMA_D_MUL = INDEX_FMA_BASE + 10;
const UINT32 INDEX_FPMA = INDEX_FMA_BASE + 11;
const UINT32 INDEX_FPMA_ADD = INDEX_FMA_BASE + 12;
const UINT32 INDEX_FPMA_MUL = INDEX_FMA_BASE + 13;
const UINT32 INDEX_FMS = INDEX_FMA_BASE + 14;
const UINT32 INDEX_FMS_SUB = INDEX_FMA_BASE + 15;
const UINT32 INDEX_FMS_MUL = INDEX_FMA_BASE + 16;
const UINT32 INDEX_FMS_S = INDEX_FMA_BASE + 17;
const UINT32 INDEX_FMS_S_SUB = INDEX_FMA_BASE + 18;
const UINT32 INDEX_FMS_S_MUL = INDEX_FMA_BASE + 19;
const UINT32 INDEX_FMS_D = INDEX_FMA_BASE + 20;
const UINT32 INDEX_FMS_D_SUB = INDEX_FMA_BASE + 21;
const UINT32 INDEX_FMS_D_MUL = INDEX_FMA_BASE + 22;
const UINT32 INDEX_FPMS = INDEX_FMA_BASE + 23;
const UINT32 INDEX_FPMS_SUB = INDEX_FMA_BASE + 24;
const UINT32 INDEX_FPMS_MUL = INDEX_FMA_BASE + 25;
const UINT32 INDEX_FNMA = INDEX_FMA_BASE + 26;
const UINT32 INDEX_FNMA_ADD = INDEX_FMA_BASE + 27;
const UINT32 INDEX_FNMA_MUL = INDEX_FMA_BASE + 28;
const UINT32 INDEX_FNMA_S = INDEX_FMA_BASE + 29;
const UINT32 INDEX_FNMA_S_ADD = INDEX_FMA_BASE + 30;
const UINT32 INDEX_FNMA_S_MUL = INDEX_FMA_BASE + 31;
const UINT32 INDEX_FNMA_D = INDEX_FMA_BASE + 32;
const UINT32 INDEX_FNMA_D_ADD = INDEX_FMA_BASE + 33;
const UINT32 INDEX_FNMA_D_MUL = INDEX_FMA_BASE + 34;
const UINT32 INDEX_FPNMA = INDEX_FMA_BASE + 35;
const UINT32 INDEX_FPNMA_ADD = INDEX_FMA_BASE + 36;
const UINT32 INDEX_FPNMA_MUL = INDEX_FMA_BASE + 37;

const UINT32 INDEX_SPECIAL_END = INDEX_FMA_BASE + 38;

/* ===================================================================== */
/*Types*/
/* ===================================================================== */

typedef enum {
	measure_opcode = 0,
	measure_category = 1,
	measure_ilen = 2,
	measure_iform = 3
} measurement_t;

typedef UINT32 stat_index_t;

typedef UINT64 COUNTER;

typedef map<UINT32, COUNTER> stat_map_t;

#if defined(__GNUC__)
#  if defined(TARGET_MAC) || defined(TARGET_WINDOWS)
#    define ALIGN_LOCK __attribute__ ((aligned(16)))
#  else
#    define ALIGN_LOCK __attribute__ ((aligned(64)))
#  endif
#else
# define ALIGN_LOCK __declspec(align(64))
#endif

typedef struct {
	char pad0[64];
	PIN_LOCK ALIGN_LOCK lock; /* for mediating output */
	char pad1[64];
	PIN_LOCK ALIGN_LOCK bbl_list_lock; /* for the bbl list */
}ALIGN_LOCK locks_t;

/* ===================================================================== */

class CSTATS {
public:
	CSTATS() {
		clear();
	}

	stat_map_t unpredicated;
	stat_map_t predicated;
	stat_map_t predicated_true;

	VOID clear() {
		unpredicated.erase(unpredicated.begin(), unpredicated.end());
		predicated.erase(predicated.begin(), predicated.end());
		predicated_true.erase(predicated_true.begin(), predicated_true.end());
	}
};

class BBLSTATS {
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
	}
	;
};

class thread_data_t {
public:
	thread_data_t() {
	}
	CSTATS cstats;

	vector<COUNTER> block_counts;

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
CSTATS GlobalStatsStatic;  // summary stats for static analysis
CSTATS GlobalStatsDynamic; // summary stats for dynamic analysis
LOCALVAR vector<BBLSTATS*> statsList;
THREADID printTraceThreadId;
UINT32 maxThreads;
UINT32 numThreads = 0;
UINT32 timeInterval;
thread_data_t* threadDataArray;
BOOL traceEnabled = true;


const UINT32 MAX_INSTRUCTION_CODES = 1550;
const UINT32 MAX_CATEGORY_CODES = 1550;
const UINT32 MAX_EXTENSION_CODES = 1550;
const UINT32 MAX_IFORMS_CODES = 1550;



/* ===================================================================== */

LOCALFUN bool IsScalarSimd(INS ins) {
	xed_decoded_inst_t* xedd = INS_XedDec(ins);
	return xed_decoded_inst_get_attribute(xedd, XED_ATTRIBUTE_SIMD_SCALAR);
}

/* ===================================================================== */
/* index functions*/
/* ===================================================================== */

BOOL IsMemReadIndex(UINT32 i) {
	return (INDEX_MEM_READ_SIZE <= i && i < INDEX_MEM_READ_SIZE + MAX_MEM_SIZE);
}

BOOL IsMemWriteIndex(UINT32 i) {
	return (INDEX_MEM_WRITE_SIZE <= i && i < INDEX_MEM_WRITE_SIZE + MAX_MEM_SIZE);
}

/* ===================================================================== */
LOCALFUN UINT32 INS_GetIndex(INS ins) {
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
	case measure_iform: {
		xed_decoded_inst_t* xedd = INS_XedDec(ins);
		xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum(xedd);
		index = static_cast<UINT32>(iform);
	}
		break;
	}
	return index;
}
/* ===================================================================== */

LOCALFUN UINT32 IndexStringLength(BBL bbl, BOOL memory_access_profile) {
	UINT32 count = 0;

	for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
		count++; // one for the ins
		if (measurement != measure_iform)
			count++;  // one for the ISA extension.

		if (measurement == measure_opcode && memory_access_profile) {
			if (INS_IsMemoryRead(ins))
				count++;   // for size

			if (INS_IsStackRead(ins))
				count++;

			if (INS_IsIpRelRead(ins))
				count++;

			if (INS_IsMemoryWrite(ins))
				count++; // for size

			if (INS_IsStackWrite(ins))
				count++;

			if (INS_IsIpRelWrite(ins))
				count++;

			if (INS_IsAtomicUpdate(ins))
				count++;

			if (IsScalarSimd(ins))
				count++;
		}
	}

	return count;
}

/* ===================================================================== */
LOCALFUN UINT32 MemsizeToIndex(UINT32 size, BOOL write) {
	return (write ? INDEX_MEM_WRITE_SIZE : INDEX_MEM_READ_SIZE) + size;
}

/* ===================================================================== */
LOCALFUN stat_index_t* INS_GenerateIndexString(INS ins, stat_index_t *stats,
		BOOL memory_access_profile) {
	*stats++ = INS_GetIndex(ins);
	if (measurement != measure_iform)
		*stats++ = INS_Extension(ins) + INDEX_EXTENSION;

	if (measurement == measure_opcode && memory_access_profile) {
		if (INS_IsMemoryRead(ins))
			*stats++ = MemsizeToIndex(INS_MemoryReadSize(ins), 0);
		if (INS_IsMemoryWrite(ins))
			*stats++ = MemsizeToIndex(INS_MemoryWriteSize(ins), 1);

		if (INS_IsAtomicUpdate(ins))
			*stats++ = INDEX_MEM_ATOMIC;

		if (INS_IsStackRead(ins))
			*stats++ = INDEX_STACK_READ;
		if (INS_IsStackWrite(ins))
			*stats++ = INDEX_STACK_WRITE;

		if (INS_IsIpRelRead(ins))
			*stats++ = INDEX_IPREL_READ;
		if (INS_IsIpRelWrite(ins))
			*stats++ = INDEX_IPREL_WRITE;

		if (IsScalarSimd(ins))
			*stats++ = INDEX_SCALAR_SIMD;
	}

	return stats;
}

/* ===================================================================== */

LOCALFUN string IndexToString(UINT32 index) {
	if (measurement == measure_iform) {
		return xed_iform_enum_t2str(static_cast<xed_iform_enum_t>(index));
	}

	if (INDEX_SPECIAL <= index && index < INDEX_SPECIAL_END) {
		if (index == INDEX_TOTAL)
			return "*total";
		else if (IsMemReadIndex(index))
			return "*mem-read-" + decstr(index - INDEX_MEM_READ_SIZE);
		else if (IsMemWriteIndex(index))
			return "*mem-write-" + decstr(index - INDEX_MEM_WRITE_SIZE);
		else if (index == INDEX_MEM_ATOMIC)
			return "*mem-atomic";
		else if (index == INDEX_STACK_READ)
			return "*stack-read";
		else if (index == INDEX_STACK_WRITE)
			return "*stack-write";
		else if (index == INDEX_IPREL_READ)
			return "*iprel-read";
		else if (index == INDEX_IPREL_WRITE)
			return "*iprel-write";
		else if (index == INDEX_SCALAR_SIMD)
			return "*scalar-simd";
		else if (index >= INDEX_EXTENSION
				&& index < INDEX_EXTENSION + MAX_EXTENSION)
			return "*isa-ext-" + EXTENSION_StringShort(index - INDEX_EXTENSION);

		else if (index == INDEX_FMA)
			return "*FMA";
		else if (index == INDEX_FMA_ADD)
			return "*FMA_ADD";
		else if (index == INDEX_FMA_MUL)
			return "*FMA_MUL";
		else if (index == INDEX_FMA_S)
			return "*FMA_S";
		else if (index == INDEX_FMA_S_ADD)
			return "*FMA_S_ADD";
		else if (index == INDEX_FMA_S_MUL)
			return "*FMA_S_MUL";
		else if (index == INDEX_FMA_D)
			return "*FMA_D";
		else if (index == INDEX_FMA_D_ADD)
			return "*FMA_D_ADD";
		else if (index == INDEX_FMA_D_MUL)
			return "*FMA_D_MUL";
		else if (index == INDEX_FPMA)
			return "*FPMA";
		else if (index == INDEX_FPMA_ADD)
			return "*FPMA_ADD";
		else if (index == INDEX_FPMA_MUL)
			return "*FPMA_MUL";
		else if (index == INDEX_FMS)
			return "*FMS";
		else if (index == INDEX_FMS_SUB)
			return "*FMS_SUB";
		else if (index == INDEX_FMS_MUL)
			return "*FMS_MUL";
		else if (index == INDEX_FMS_S)
			return "*FMS_S";
		else if (index == INDEX_FMS_S_SUB)
			return "*FMS_S_SUB";
		else if (index == INDEX_FMS_S_MUL)
			return "*FMS_S_MUL";
		else if (index == INDEX_FMS_D)
			return "*FMS_D";
		else if (index == INDEX_FMS_D_SUB)
			return "*FMS_D_SUB";
		else if (index == INDEX_FMS_D_MUL)
			return "*FMS_D_MUL";
		else if (index == INDEX_FPMS)
			return "*FPMS";
		else if (index == INDEX_FPMS_SUB)
			return "*FPMS_SUB";
		else if (index == INDEX_FPMS_MUL)
			return "*FPMS_MUL";
		else if (index == INDEX_FNMA)
			return "*FNMA";
		else if (index == INDEX_FNMA_ADD)
			return "*FNMA_ADD";
		else if (index == INDEX_FNMA_MUL)
			return "*FNMA_MUL";
		else if (index == INDEX_FNMA_S)
			return "*FNMA_S";
		else if (index == INDEX_FNMA_S_ADD)
			return "*FNMA_S_ADD";
		else if (index == INDEX_FNMA_S_MUL)
			return "*FNMA_S_MUL";
		else if (index == INDEX_FNMA_D)
			return "*FNMA_D";
		else if (index == INDEX_FNMA_D_ADD)
			return "*FNMA_D_ADD";
		else if (index == INDEX_FNMA_D_MUL)
			return "*FNMA_D_MUL";
		else if (index == INDEX_FPNMA)
			return "*FPNMA";
		else if (index == INDEX_FPNMA_ADD)
			return "*FPNMA_ADD";
		else if (index == INDEX_FPNMA_MUL)
			return "*FPNMA_MUL";

		else {
			ASSERTX(0);
			return "";
		}
	} else if (measurement == measure_ilen) {
		ostringstream s;
		s << "ILEN-" << index;
		return s.str();
	} else if (measurement == measure_opcode) {
		return OPCODE_StringShort(index);
	} else if (measurement == measure_category) {
		return CATEGORY_StringShort(index);
	}
	ASSERTX(0);
	return "";

}

/*========================================================================*/

LOCALFUN thread_data_t* get_tls(THREADID tid) {
	// thread_data_t* tdata =
	//       static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, tid));
	// return tdata;
	return &threadDataArray[tid];
}

/* ===================================================================== */

VOID zero_stats(THREADID tid) {
	thread_data_t* tdata = get_tls(tid);
	tdata->cstats.clear();
	UINT32 limit = tdata->size();
	for (UINT32 i = 0; i < limit; i++)
		tdata->block_counts[i] = 0;
}

/* ===================================================================== */

VOID UpdateLocalStats(THREADID tid)
{
	thread_data_t* tdata = get_tls(tid);

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

		if (b && b->_stats) //the string with the block statistics exists
			//recall that this string is formed by all opcodes
			//works like this: ADDMOVADDADDADD, for each time ADD is found in this
			//string, the number of times the block was executed is appended
			//to the array that maps all opcodes. this can be highly optmilized
			//later by pre-computing it.
			for (const stat_index_t* stats = b->_stats; *stats; stats++) {
				tdata->cstats.unpredicated[*stats] += bcount;
			}
	}
	PIN_ReleaseLock(&locks.bbl_list_lock);
}

//TODO: Make this function compatible with accurate analysis
VOID updateGlobalStats() {
	thread_data_t* tdata;

	GlobalStatsDynamic.clear();
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
					GlobalStatsDynamic.unpredicated[*stats] += bcount;
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
VOID PrintCSVHeader(ofstream& out, UINT64 timestamp, CSTATS& stats,
		BOOL predicated_true)
{

	map<UINT32, bool> m;

	stat_map_t *statss;
	statss = predicated_true ? &stats.predicated_true : &stats.unpredicated;

	if(measurement == measure_opcode){
		for(UINT32 a=0; a < MAX_INSTRUCTION_CODES; a++ ){
			m[a] = true;
		}
	}
	if(measurement == measure_category){
		for(UINT32 a=0; a < MAX_CATEGORY_CODES; a++ ){
			m[a] = true;
		}
	}
	if(measurement == measure_iform){
		for(UINT32 a=0; a < MAX_IFORMS_CODES; a++ ){
			m[a] = true;
		}
	}



	COUNTER tu = 0;
	for (stat_map_t::iterator it = statss->begin(); it != statss->end(); it++) {
				if (measurement == measure_iform || it->first < INDEX_SPECIAL)
					tu += it->second;
				m[it->first] = true;
	}
	out << "!Timestamp;";
	for (map<UINT32, bool>::iterator it = m.begin(); it != m.end(); it++) {
		stat_map_t::iterator s;
		COUNTER up = 0;
		UINT32 indx = it->first;
		s = statss->find(indx);
		if (s != statss->end())
			up = s->second;

		if (up == 0)
			continue;
		out << IndexToString(indx) << ";";
	}
	out << "*total;" << endl;

	out << timestamp << ";";
	for (map<UINT32, bool>::iterator it = m.begin(); it != m.end(); it++) {
		stat_map_t::iterator s;
		COUNTER up = 0;
		UINT32 indx = it->first;
		s = statss->find(indx);
		if (s != statss->end())
			up = s->second;

		if (up == 0)
			continue;
		out << up << ";";
	}
	// print the totals
	out << tu << endl;


}

VOID PrintStatsToCSV(ofstream& out, UINT64 timestamp, CSTATS& stats,
		BOOL predicated_true) {
	// Compute the "total" bin. Stop at the INDEX_SPECIAL for all histograms
	// except the iform. Iforms do not use the special rows, so we count everything.

	// build a map of the valid stats index values for all 3 tables.
	map<UINT32, bool> m;

	stat_map_t *statss;
	statss = predicated_true ? &stats.predicated_true : &stats.unpredicated;

	COUNTER tu = 0;
	for (stat_map_t::iterator it = statss->begin(); it != statss->end(); it++) {
		if (measurement == measure_iform || it->first < INDEX_SPECIAL)
			tu += it->second;
		m[it->first] = true;
	}

	out << "!Timestamp;";
	for (map<UINT32, bool>::iterator it = m.begin(); it != m.end(); it++) {
		stat_map_t::iterator s;
		COUNTER up = 0;
		UINT32 indx = it->first;
		s = statss->find(indx);
		if (s != statss->end())
			up = s->second;

		if (up == 0)
			continue;
		out << IndexToString(indx) << ";";
	}
	out << "*total;" << endl;

	out << timestamp << ";";
	for (map<UINT32, bool>::iterator it = m.begin(); it != m.end(); it++) {
		stat_map_t::iterator s;
		COUNTER up = 0;
		UINT32 indx = it->first;
		s = statss->find(indx);
		if (s != statss->end())
			up = s->second;

		if (up == 0)
			continue;
		out << up << ";";
	}
	// print the totals
	out << tu << endl;
}
/* ===================================================================== */
VOID PrintStats(ofstream& out, CSTATS& stats, BOOL predicated_true,
		const string& title, THREADID tid) {
	out << "#\n# " << title << "\n#\n";
	if (tid != INVALID_THREADID)
		out << "# TID " << tid << "\n";
	out << "# ";
	const char *label = 0;
	if (measurement == measure_opcode)
		label = "opcode";
	else if (measurement == measure_ilen)
		label = "inslen";
	else if (measurement == measure_category)
		label = "category";
	else if (measurement == measure_iform)
		label = "iform";

	if (label)
		out << ljstr(label, 24);

	out << setw(16) << "count";
	if (predicated_true)
		out << "    count-predicated-true";
	out << "\n#\n";

	// Compute the "total" bin. Stop at the INDEX_SPECIAL for all histograms
	// except the iform. Iforms do not use the special rows, so we count everything.

	// build a map of the valid stats index values for all 3 tables.
	map<UINT32, bool> m;

	COUNTER tu = 0;
	for (stat_map_t::iterator it = stats.unpredicated.begin();
			it != stats.unpredicated.end(); it++) {
		if (measurement == measure_iform || it->first < INDEX_SPECIAL)
			tu += it->second;
		m[it->first] = true;
	}

	COUNTER tpt = 0;
	for (stat_map_t::iterator it = stats.predicated_true.begin();
			it != stats.predicated_true.end(); it++) {
		if (measurement == measure_iform || it->first < INDEX_SPECIAL)
			tpt += it->second;
		m[it->first] = true;
	}

	for (map<UINT32, bool>::iterator it = m.begin(); it != m.end(); it++) {
		stat_map_t::iterator s;
		COUNTER up = 0;
		UINT32 indx = it->first;

		s = stats.unpredicated.find(indx);
		if (s != stats.unpredicated.end())
			up = s->second;

		if (up == 0)
			continue;

		out << ljstr(IndexToString(indx), 25) << " " << setw(16) << up;
		if (predicated_true) {
			COUNTER prt = 0;
			s = stats.predicated_true.find(indx);
			if (s != stats.predicated_true.end()) {
				prt = s->second;
				out << " " << setw(16) << prt;
			}
		}
		out << endl;
	}

	// print the totals
	out << ljstr("*total", 25) << " " << setw(16) << tu;
	if (predicated_true)
		out << " " << setw(16) << tpt;
	out << endl;
}
/* ===================================================================== */
VOID DumpStats(ofstream& out, CSTATS& stats, BOOL predicated_true,
		const string& title, THREADID tid) {
	out << "#\n# " << title << "\n#\n";
	if (tid != INVALID_THREADID)
		out << "# TID " << tid << "\n";
	out << "# ";
	const char *label = 0;
	if (measurement == measure_opcode)
		label = "opcode";
	else if (measurement == measure_ilen)
		label = "inslen";
	else if (measurement == measure_category)
		label = "category";
	else if (measurement == measure_iform)
		label = "iform";

	if (label)
		out << ljstr(label, 24);

	out << setw(16) << "count";
	if (predicated_true)
		out << "    count-predicated-true";
	out << "\n#\n";

	// Compute the "total" bin. Stop at the INDEX_SPECIAL for all histograms
	// except the iform. Iforms do not use the special rows, so we count everything.

	// build a map of the valid stats index values for all 3 tables.
	map<UINT32, bool> m;

	COUNTER tu = 0;
	for (stat_map_t::iterator it = stats.unpredicated.begin();
			it != stats.unpredicated.end(); it++) {
		if (measurement == measure_iform || it->first < INDEX_SPECIAL)
			tu += it->second;
		m[it->first] = true;
	}

	COUNTER tpt = 0;
	for (stat_map_t::iterator it = stats.predicated_true.begin();
			it != stats.predicated_true.end(); it++) {
		if (measurement == measure_iform || it->first < INDEX_SPECIAL)
			tpt += it->second;
		m[it->first] = true;
	}

	for (map<UINT32, bool>::iterator it = m.begin(); it != m.end(); it++) {
		stat_map_t::iterator s;
		COUNTER up = 0;
		UINT32 indx = it->first;

		s = stats.unpredicated.find(indx);
		if (s != stats.unpredicated.end())
			up = s->second;

		if (up == 0)
			continue;

		out << ljstr(IndexToString(indx), 25) << " " << setw(16) << up;
		if (predicated_true) {
			COUNTER prt = 0;
			s = stats.predicated_true.find(indx);
			if (s != stats.predicated_true.end()) {
				prt = s->second;
				out << " " << setw(16) << prt;
			}
		}
		out << endl;
	}

	// print the totals
	out << ljstr("*total", 25) << " " << setw(16) << tu;
	if (predicated_true)
		out << " " << setw(16) << tpt;
	out << endl;
}

/* ===================================================================== */
VOID printTraceThread(VOID * arg) {

	while(traceEnabled)
	{
//		PIN_Sleep(timeInterval);
//		updateStats();
//		*out << "Waited 1 second = " << get_timestamp() << endl;
//		// emit the dynamic stats
//		*out << "# EMIT_DYNAMIC_STATS"  << endl;
//		DumpStats(*out, GlobalStatsDynamic, KnobProfilePredicated, "$dynamic-counts",0);
//		*out << "# END_DYNAMIC_STATS" <<  endl;

		PIN_Sleep(timeInterval);
		updateGlobalStats();
		PrintStatsToCSV(*out, get_timestamp() ,GlobalStatsDynamic, KnobProfilePredicated);

	}

}

/* ===================================================================== */

VOID emit_static_stats() {
	*out << "# EMIT_STATIC_STATS " << endl;
	DumpStats(*out, GlobalStatsStatic, false, "$static-counts",
			INVALID_THREADID);
	*out << endl << "# END_STATIC_STATS" << endl;
}

/* ===================================================================== */

void combine_dynamic_stats(unsigned int numThreads) {
	// combine all the rows from each thread in to the total variable.
	CSTATS total;
	for (THREADID i = 0; i < numThreads; i++) {
		thread_data_t* tdata = get_tls(i);

		for (stat_map_t::iterator it = tdata->cstats.unpredicated.begin();
				it != tdata->cstats.unpredicated.end(); it++) {
			stat_map_t::iterator x = total.unpredicated.find(it->first);
			if (x == total.unpredicated.end())
				total.unpredicated[it->first] = it->second;
			else
				x->second += it->second;
		}

		for (stat_map_t::iterator it = tdata->cstats.predicated.begin();
				it != tdata->cstats.predicated.end(); it++) {
			stat_map_t::iterator x = total.predicated.find(it->first);
			if (x == total.predicated.end())
				total.predicated[it->first] = it->second;
			else
				x->second += it->second;
		}

		for (stat_map_t::iterator it = tdata->cstats.predicated_true.begin();
				it != tdata->cstats.predicated_true.end(); it++) {
			stat_map_t::iterator x = total.predicated_true.find(it->first);
			if (x == total.predicated_true.end())
				total.predicated_true[it->first] = it->second;
			else
				x->second += it->second;
		}
	}

	*out << "# EMIT_GLOBAL_DYNAMIC_STATS " << endl;
	DumpStats(*out, total, false, "$global-dynamic-counts", INVALID_THREADID);
	*out << endl << "# END_GLOBAL_DYNAMIC_STATS" << endl;

}

/*=============================================================================*/
/* Analysis tools */
/*=============================================================================*/
VOID validate_bbl_count(THREADID tid, ADDRINT block_count_for_trace) {
	thread_data_t* tdata = get_tls(tid);
	tdata->resize(block_count_for_trace + 1);
}

VOID PIN_FAST_ANALYSIS_CALL docount_bbl(ADDRINT block_id, THREADID tid) {
	// thread_data_t* tdata = get_tls(tid);
	// tdata->block_counts[block_id] += 1;
	//get_tls(tid)->block_counts[block_id] += 1;
	threadDataArray[tid].block_counts[block_id] += 1;
}

VOID docount_predicated_true(UINT32 index, THREADID tid) {
	thread_data_t* tdata = get_tls(tid);
	stat_map_t::iterator i = tdata->cstats.predicated_true.find(index);
	if (i == tdata->cstats.predicated_true.end())
		tdata->cstats.predicated_true[index] = 1;
	else
		i->second += 1;
}
/*=============================================================================*/
/* Thread management specific functions */
/*=============================================================================*/

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
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

	//thread_data_t* tdata = new thread_data_t;
	// remember my pointer for later
	PIN_SetThreadData(tls_key, &threadDataArray[tid], tid);

}

// This function is called when the thread exits
VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	*out << "#Thread[" << decstr(tid) << "] = finished" << endl;

}
/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v) {
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
	traceEnabled=false;
    PIN_WaitForThreadTermination(printTraceThreadId, PIN_INFINITE_TIMEOUT, NULL);
    updateGlobalStats();
//	*out << "# FINI: end of program" << endl;
//    *out << "# EMIT_FINAL_DYNAMIC_STATS"  << endl;
//	DumpStats(*out, GlobalStatsDynamic, KnobProfilePredicated, "$dynamic-counts",0);
//	*out << "# END_FINAL_DYNAMIC_STATS" <<  endl;

	PrintStatsToCSV(*out, get_timestamp() ,GlobalStatsDynamic, KnobProfilePredicated);
    out->close();
}

/* ===================================================================== */
/* Static analysis */
/* ===================================================================== */

VOID Image(IMG img, VOID * v) {
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
						GlobalStatsStatic.predicated[*start]++;
					}
				} else {
					for (stat_index_t *start = array; start < end; start++) {
						GlobalStatsStatic.unpredicated[*start]++;
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

int main(int argc, CHAR **argv) {
	PIN_InitSymbols();
	if (PIN_Init(argc, argv))
		return Usage();

	//process command line parameters/knobs
	timeInterval = KnobTimer.Value();
	maxThreads = KnobThreads.Value();
	threadDataArray = new thread_data_t[maxThreads];

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
	if (KnobIformTracer.Value()) {
		measurement = measure_iform;
	}

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
