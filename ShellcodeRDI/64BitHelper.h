#if defined(_WIN64)
extern VOID AlignRSP( VOID );

VOID Begin( VOID )
{
	// Call the ASM stub that will guarantee 16-byte stack alignment.
	// The stub will then call the ExecutePayload.
	AlignRSP();
}
#endif