# Forked from edub0's EXLAP project found here: https://github.com/edub0/EXLAP  Please see his github for more details.

New utility "parse_exlap_log.py" added to convert the original EXLAP data stored as XML into a csv file.  This utility iterates through the XML blobs and handles the edge cases around different blob types.

# EXLAP 1.3 Schema and Python interface
 
This projects purpose is to demonstrate the EXLAP protocol using python. You
 can read much more about EXLAP, its function and purpose in the /docs folder.

Information about EXLAP was released under Creative Common license making this
 project possible.

*Credentials* (creds.py) must be provided to speak to EXLAP authenticated commands.
 
Demonstration of protocol is limited without authentication. It is possible to test
connectivity by issuing the Req_Dir('*') command to an exlap server.

To use this project to speak to an exlap server, one must provide credentials
and the ip address of the exlap server. Modify the main.py file
with the ip address and commands you wish to issue the server.

This project required a patch to asyncio, and assumes python 3.10.9 is present.
Likely, it will work on earlier version of python 3.
 
 
## Project Folder Structure

- **src/**      src code
- **docs/**     project documentation, exlap schema files
- **dep/**      project dependencies such as python patches and imports
- **samples/**  demonstrations of basic project capabilties

Some future idea for this project are better parsing of exlap responses

- Validation of data sources and format ()

- Test access over USB (the protocol says it supports it)


Known Issues:

EXLAP Authentication was not as documented in the schema. MD5 appears no longer
used.

Websockets connection upgrade did not function as documented in schema.

