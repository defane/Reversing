## Overview

During debugging of chrome.dll, the knowledge of function name in disassembler such as Ghidra or IDA. Even if the PDBs of public release are available, the amount of information in those big file leading to slow loading into the disassembler. The size PDB can go upto 4GB.

To address that, a partial loading can be use to just resolve the name of function.

The toolset is written in two parts:

1. Extract function name from PDB using Rust app and store the information into a SQLite database
2. Use information stored in SQLite database to edit function name and add comment about the function name structure

## Usage

### 1 - Extract from PDB

Dependency:

* `cargo`

To run the tools, goto the **tools directory** and then run the following command:

`cargo run <PDB_path> <DB_path>`

The DB path can point a non-existing file. The tool will initialize the database structure

### 2 - Insert into ghidra

Dependency:

* `Ghidra`
* `sqlite-jdbc` for SQLite driver in Java. It can be download from https://github.com/xerial/sqlite-jdbc and the jar can be installed in this location `<ROOT_GHIDRA>\Ghidra\Configurations\Public_Release\lib\`

Installation:

1. Install the script `LoadPdbFunctionName.java` with it associated propertie file `LoadPdbFunctionName.properties` in folder such as `%UserProfile%\ghidra_scripts`.
2. Add the folder in Ghidra as scripts folder in *Script Manager* panel.

Run:

* Run the script from *Script Manager* and select the DB path from the File chooser dialogue