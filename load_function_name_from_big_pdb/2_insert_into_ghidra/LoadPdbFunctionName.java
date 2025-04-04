// Load Function name from PDB info stored in database with companion tools.
//@author Stéphane EMMA
//@category COS.PDB

import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.sourcemap.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.sql.Connection;  
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JFileChooser;

import docking.widgets.filechooser.LocalFileChooserModel;


public class LoadPdbFunctionName extends GhidraScript {
	private class ResultParseFunctionName {
		public String name;
		public Namespace namespace;
		public String signature;
		@Override
		public String toString() {
			String output = "";
			
			output += "name="+name+"\n";
			output += "namespace="+namespace+"\n";
			output += "signature="+signature;
			
			return output; 
		}
	}
	private void log(String text) {
		//println(text);
		return;
	}
	
    public void run() throws Exception {
    	//*
    	File file1 = askFile("FILE", "Choose file:");
		println("file was: " + file1);
    	Class.forName("org.sqlite.JDBC");  
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + file1.getPath()); 
    	SymbolTable symtab = currentProgram.getSymbolTable();
    	Address base_addr = currentProgram.getImageBase();
    	FunctionManager fun_manager = currentProgram.getFunctionManager();
    	String pdb_guid = currentProgram.getMetadata().get("PDB GUID");
    	println("Local PDB GUID: " + pdb_guid);
    	Statement statement = connection.createStatement();
    	ResultSet resultSet = statement  
                .executeQuery("SELECT value FROM pdb_metadata WHERE key = 'guid' LIMIT 1;");
    	
    	if (!resultSet.next()) {
    		println("Unable to obtain PDB GUID from DB.");
    		return;
    	}
    	
    	String db_pdb_guid = resultSet.getString(1);
    	println("DB PDB GUID: " + db_pdb_guid);
    	
    	if (!db_pdb_guid.equals(pdb_guid)) {
    		println("PDB GUID dismatches");
    		return;
    	}

    	println("Base address: " + base_addr.toString());
   
        resultSet = statement  
                .executeQuery("SELECT rva, name, signature, original_name FROM pdb_function;");
        while(resultSet.next()) {
        	long rva = resultSet.getInt(1);
        	String name = resultSet.getString(2);
        	String signature =  resultSet.getString(3);
        	String original_name =  resultSet.getString(4);
        	Address addr = base_addr.add(rva);
        	log("RVA: " + String.format("0x%02x", rva));
        	log("Addr: " + String.format("0x%02x", rva + base_addr.getAddressableWordOffset()));
        	log("Name: " + name);
        	Symbol symbol = symtab.getPrimarySymbol(addr);
        	log("Symbol: " + symbol);
        	if (symbol == null) continue;
        	
        	Function current_fun = fun_manager.getFunctionAt(addr);
        	log("Function: " + current_fun);
        	if (current_fun == null) continue;
        	log("Function: " + current_fun);
        	
        	String comment = "Original symbole name: " + original_name;
        	ResultParseFunctionName res = null;
        	try {
        		res = parse_function_name(name, signature);
        		if (res != null) {
        			current_fun.setName(res.name, SourceType.USER_DEFINED);
            		current_fun.setParentNamespace(res.namespace);
            		comment =  "Signature: " + res.signature + "\n";
            		comment += "Original symbole name: " + original_name;
        		}
        	} catch(InvalidInputException e) {
        		println("Exception="+e);
        		println("Name="+name);
        		println("Res="+res);
        	} catch(Exception e){
        		println(e.getClass().getCanonicalName());
        	}
        	
        	currentProgram.getListing().setComment(addr, CodeUnit.PRE_COMMENT, comment);
        	log("Function: " + current_fun);

        }//*/
        
    }
    private ResultParseFunctionName parse_function_name(String function_name, String signature) {
    	try {
	    	ResultParseFunctionName output = new ResultParseFunctionName();
	    	
	    	if (function_name == null) return null;
	    	
	    	output.signature = signature;
	    	
	    	Pattern pattern = Pattern.compile("^((?:[^<:]+::)+)([^<\\\\(]+)");  
		    Matcher matcher = pattern.matcher(function_name);
		    if (!matcher.find()) {
		    	return null;
		    }
		    output.name = matcher.group(2);
		    output.name = output.name.replaceAll(" ", "_").replaceAll("[`']", "");
		    
		    String namespace = matcher.group(1);
		    // remove two last character '::'
		    namespace = namespace.substring(0, namespace.length() - 2);
		    // According documentation must start with root namespace
		    namespace = "Global::" + namespace;

	        
	    	output.namespace = create_namespace(namespace);
	    	return output;
    	} catch(NullPointerException e) {
    		return null;
    	} catch(Exception e) {
    		println("Exception from parse_function_name: " + e.getClass().getCanonicalName());
    		//e.printStackTrace();
    	}
    	return null;
    	
    	
    }
    private Namespace create_namespace(String namespaces) {
    	Namespace newNamespace = null;
    	try {
    		namespaces = namespaces.replaceAll(" ", "_").replaceAll("['`]", "");
    	    Namespace rootNamespace = currentProgram.getGlobalNamespace();
    	    newNamespace = NamespaceUtils.createNamespaceHierarchy(namespaces, rootNamespace, currentProgram, SourceType.USER_DEFINED);
    	    log("Namespace created: " + newNamespace.getName(true));
    	} catch (Exception e) {
    	    println("Exception from create_namespace: " + e.getMessage());
    	}
    	return newNamespace;
    }
}
