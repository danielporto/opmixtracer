
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdlib.h>

/*
//Helpers
*/


/* ================================================================== */
// Global variables 
/* ================================================================== */
const UINT32 MAX_INSTRUCTIONS=16777215; //3 byte lenght opcodes
UINT64 STATS[MAX_INSTRUCTIONS];
std::ofstream *out = 0;
/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "opcodescount.out", "report of all opcodes used by the program");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the total of all opcodes and their respecive integer " << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
VOID docount(UINT64 * counter)
{
    (*counter)++;
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


VOID DumpStats(ofstream& out, UINT64 *stats, const string& title)
{
    out <<
        "#\n"
        "# " << title << "\n"
        "#\n"
        "#num extension   count\n";

    for ( UINT32 i = 0; i < MAX_INSTRUCTIONS; i++)
    {
        out << decstr(i,3) << " " <<  ljstr(OPCODE_StringShort(i),15) << decstr( stats[i],12) << endl;
    }
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
    *out <<  "OpCodesCounter analysis results: " << endl;
    DumpStats(*out,STATS,"Counting opcodes");
    *out <<  "===============================================" << endl;
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
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )  {  return Usage();   }
    
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

    // Register function to be called to instrument traces
    INS_AddInstrumentFunction(Instruction, 0);
    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by OpCodesCounter" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
