#!/usr/bin/env bash

GHIDRA=/opt/ghidra/support/analyzeHeadless
SCRIPTS=$PWD/ghidra_scripts
PROJECT=$PWD/ghidra_project

mkdir $PROJECT

LDC=$(which ldc2)
CXX=$(which g++)
SWIFT=$(which swiftc)
RUST=$(which rustc)

$CXX -std=c++23 -g -O0 -o $PWD/sample/target_cpp $PWD/sample/target.cpp
$LDC -g -O0 --edition=2024 -preview=all -of=$PWD/sample/target_d $PWD/sample/target.d
$RUST --edition=2024 $PWD/sample/target.rs --crate-type bin -C debuginfo=2 --crate-name target_rust -o $PWD/sample/target_rust
$SWIFT -g -O -o $PWD/sample/target_swift $PWD/sample/target.swift

$GHIDRA $PROJECT CppProject   -import $PWD/sample/target_cpp   -scriptPath $SCRIPTS -postScript ExtractFunctions.java -deleteProject
$GHIDRA $PROJECT DProject     -import $PWD/sample/target_d     -scriptPath $SCRIPTS -postScript DemangleD.java         -deleteProject
$GHIDRA $PROJECT RustProject  -import $PWD/sample/target_rust  -scriptPath $SCRIPTS -postScript DemangleRust.java      -deleteProject
$GHIDRA $PROJECT SwiftProject -import $PWD/sample/target_swift -scriptPath $SCRIPTS -postScript DemangleSwift.java     -deleteProject