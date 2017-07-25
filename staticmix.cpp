
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "static-", "specify file prefix for static analysis output");
KNOB<BOOL>   KnobCategory(KNOB_MODE_WRITEONCE,                "pintool",
    "c", "0", "static analize instruction category");
KNOB<BOOL>   KnobInstructions(KNOB_MODE_WRITEONCE,                "pintool",
    "i", "1", "static analize instructions");
KNOB<BOOL>   KnobExtensions(KNOB_MODE_WRITEONCE,                "pintool",
    "e", "0", "static analize instruction extension");
KNOB<BOOL>   KnobNoSharedLibs(KNOB_MODE_WRITEONCE,  "pintool",
    "no_shared_libs", "0", "include all libraries and dependencies");
KNOB<BOOL>   KnobSplitPredicatedInstructions(KNOB_MODE_WRITEONCE,  "pintool",
    "split_type", "0", "print predicated and unpredicated instruction separatedly");
KNOB<BOOL>   KnobPredicatedInstructions(KNOB_MODE_WRITEONCE,  "pintool",
    "p", "0", "Enable predicated / unpredicated instructions");


/* ================================================================== */
// Global variables 
/* ================================================================== */
const UINT32 MAX_CATEGORIES=80; 
const UINT32 MAX_EXTENSIONS=80; 
const UINT32 MAX_INSTRUCTIONS=1530; //3 byte lenght opcodes, many unused.
UINT64 StaticData[MAX_INSTRUCTIONS];
UINT64 totalInstuctions=0;
string report = "";
std::ofstream *out = 0;
 
/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the static analysis of the instruction of the binary " << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}


/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
/*!
 * Print out header of results.
 * @param[in]   output          file to write data to
 * @param[in]   category        print catgory if true or instruction names instead
 */
VOID PrintCSVHeader(ofstream& output)
{
    UINT32 limit = 0; 
    string (*foo)(UINT32);

    if(KnobCategory.Value())
    {
        limit =MAX_CATEGORIES;
        foo= &CATEGORY_StringShort;
    }
    else if(KnobExtensions.Value()) 
    {    
        limit = MAX_EXTENSIONS;
        foo= &EXTENSION_StringShort;
    }
    else if (KnobInstructions.Value())
    {
        limit = MAX_INSTRUCTIONS;
        foo= &OPCODE_StringShort;
    }


    for ( UINT32 i = 0; i < limit; i++)
    {
        output <<foo(i) << ";";
    }   
    output << endl;
    output.flush();
}

VOID Print(ofstream& out, const string& text)
{
    out <<"! " << text << endl;
    out.flush();
}

VOID PrintStaticDataToCSV(ofstream& out, UINT64 *Data, UINT32 limit)
{
    for ( UINT32 i = 0; i < limit; i++)
    {
        out <<Data[i] << ";";
    }   
    out << endl;
    out.flush();
}



/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    UINT32 limit = 0; 

    if(KnobCategory.Value())
    {
        limit =MAX_CATEGORIES;
    }
    else if(KnobExtensions.Value()) 
    {    
        limit = MAX_EXTENSIONS;
    }
    else if (KnobInstructions.Value())
    {
        limit = MAX_INSTRUCTIONS;
    }

    PrintStaticDataToCSV(*out,StaticData,limit);
    *out <<  "!===============================================" << endl;
    *out <<  "!StaticMix total instructions: " << totalInstuctions << endl;
    *out <<  "!===============================================" << endl;
    out->close();
}


VOID Image(IMG img, VOID * v)
{

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            RTN_Open(rtn);
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                if(KnobCategory.Value())
                {
                    StaticData[INS_Category(ins)]++;
                }
                else{
                    StaticData[INS_Opcode(ins)]++;
                }
            }
            RTN_Close(rtn);
        }
    }
    Fini(0,0);
    exit(0);
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
    //Allow static analysis (image instrumentation)
    PIN_InitSymbols();

    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    if((KnobInstructions.Value() ^ KnobInstructions.Value()) ^ KnobExtensions.Value() ){
        cerr << "Choose one Instructuction, Category or Extension static analysis." << endl;
        return Usage();
    }
    
    //prepare output file
    report = KnobOutputFile.Value();
    if(KnobCategory.Value())
    {
     report = report+ "category-";
    }
    else if(KnobExtensions.Value()) 
    {    
     report = report + "extension-"; 
    }
    else if (KnobInstructions.Value())
    {
        report = report + "instruction-"; 
    }
    report = KnobNoSharedLibs.Value()? report+ "no_libs":report+ "with_libs";
    report = KnobSplitPredicatedInstructions.Value()?report+(KnobPredicatedInstructions.Value()?"-predicated":"-unpredicated"):report;
    report = report + ".out";
    out = new std::ofstream(report.c_str());

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    //Start static analysis
    IMG_AddInstrumentFunction(Image, 0);

    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by staticmix" << endl;
    if (!report.empty()) 
    {
        cerr << "See file " << report << " for analysis results" << endl;
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