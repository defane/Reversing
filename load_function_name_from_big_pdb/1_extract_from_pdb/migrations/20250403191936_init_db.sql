DROP TABLE IF EXISTS 'pdb_function';
CREATE TABLE 'pdb_function' (
  'rva' int NOT NULL,
  'original_name' TEXT NOT NULL,
  'name' TEXT NULL,
  'signature' TEXT NULL,
  PRIMARY KEY ('rva')
);

DROP TABLE IF EXISTS 'pdb_metadata';
CREATE TABLE 'pdb_metadata' (
  'id' INTEGER PRIMARY KEY,
  'key' TEXT NOT NULL UNIQUE,
  'value' TEXT NOT NULL
);