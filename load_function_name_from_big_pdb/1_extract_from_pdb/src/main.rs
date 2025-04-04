use indicatif::ProgressBar;
use pdb::PDB;
use sqlx::sqlite::SqliteConnectOptions;
use std::fs::File;
use std::path::Path;
use pdb::FallibleIterator;
use std::string::String;
use std::{env, panic};
use symbolic_common::{Name, NameMangling, Language};
use symbolic_demangle::{Demangle, DemangleOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3{
        println!("Usage: {} <pdb path> <sqlite path>", args[0]);
    }
    let path: &Path = Path::new(args[2].as_str());
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let pool = sqlx::sqlite::SqlitePool::connect_with(options).await.unwrap();
    sqlx::migrate!().run(&pool).await?;
    let path = Path::new(&args[1]);
    let file = File::open(&path)?;
    let mut pdb = PDB::open(file)?;

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    println!("PDB guid: {}", pdb.pdb_information().unwrap().guid);
    println!("PDB age: {}", pdb.pdb_information().unwrap().age);

    let result = sqlx::query(
        "UPDATE pdb_metadata set value = $2 WHERE key = $1")
        .bind("guid")
        .bind(String::from(pdb.pdb_information().unwrap().guid))
        .execute(&pool).await;
    let row_affected =  result.unwrap().rows_affected();
    if row_affected == 0 {
        let _result = sqlx::query(
            "INSERT INTO pdb_metadata (key, value) VALUES ($1, $2)")
            .bind("guid")
            .bind(String::from(pdb.pdb_information().unwrap().guid))
            .execute(&pool).await;
    }
    let mut symbols = symbol_table.iter();
    let mut count_insert: i64 = 0;
    let mut count_symbol_func: i64 = 0;
    let _result = sqlx::query(
        "DELETE FROM pdb_function")
        .execute(&pool).await;
    let nb_symbols: u64 = symbol_table.iter().count().unwrap() as u64;
    let pb = ProgressBar::new(nb_symbols);
    while let Some(symbol) = symbols.next()? {
        match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) if data.function => {
                count_symbol_func += 1;
                // we found the location of a function!
                let rva = u32::from(data.offset.to_rva(&address_map).unwrap_or_default());
                let rva = i64::from(rva);
                //println!("{} is {}", rva, data.name);
                let mut demangle: Option<String> = None;
                let mut try_fct_name: Option<String> = None;
                let result = panic::catch_unwind(|| {
                    let name = Name::new(data.name.to_string(), NameMangling::Mangled, Language::Cpp);
                    let _demangle = name.demangle(DemangleOptions::complete());
                });
                if result.is_ok() {
                    let name: Name<'_> = Name::new(data.name.to_string(), NameMangling::Mangled, Language::Cpp);
                    demangle = name.demangle(DemangleOptions::complete());
                    try_fct_name = name.demangle(DemangleOptions::name_only());
                }
                if demangle.is_some() {
                    let signature: String = demangle.unwrap();
                    let fct_name: String = try_fct_name.unwrap();
                    let _result = sqlx::query(
                        "INSERT INTO pdb_function (rva, original_name, signature, name)
                        VALUES ($1, $2, $3, $4)")
                        .bind(rva)
                        .bind(String::from(data.name.to_string()))
                        .bind(signature)
                        .bind(fct_name)
                        .execute(&pool).await;
                }else{
                    let _result = sqlx::query(
                        "INSERT INTO pdb_function (rva, original_name)
                        VALUES ($1, $2)")
                        .bind(rva)
                        .bind(String::from(data.name.to_string()))
                        .execute(&pool).await;
                }
                //println!("{}",try_demangle);
                match _result {
                    Ok(ref data) if data.rows_affected() > 0 => {
                        count_insert += 1;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        panic!("Oh nooooo!!! Something is wrong during DB insert :/")}
                }
            }
            _ => {}
        }
        pb.inc(1);
    }
    pb.finish();
    println!("{}/{} were extracted from PDB to DB", count_insert, count_symbol_func);
    Ok(()) 
}

