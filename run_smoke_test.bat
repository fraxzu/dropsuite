@echo off
set DROPSUITE_DATA_DIR=C:\Users\Fraxzu\Downloads\dropsuite-smoke
set RUST_LOG=dropsuite=info,dropsuite_app=info,dropsuite_core=info
start "" "%~dp0dropsuite.exe"
