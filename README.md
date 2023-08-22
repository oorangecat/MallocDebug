# Debug-friendly malloc implementation

As a part of the Reverse Engineering course in CVUT, Prague, the following debug friendly memory management library was created. 

After the import of the common malloc implementation, the MallocDebug_init replaces the old functions with the new Debug ones in the Import Address Table of the currently executing program. 

It will provide CLI logs for every issue with dynamic memory management, avoiding potential memory leaks.

This approach makes use of Windows APIs and will only work in a Windows environment.
