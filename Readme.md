🔒 File Integrity Checker



This small tool was developed to verify the integrity of important files by calculating a hash value (checksum) and comparing it with a previously stored value.



✨ Features



GUI-based: Simple operation without the command line.



Checksum Comparison: Uses the SHA-256 algorithm to create and verify hashes.



Standalone EXE: Runs without a Python environment installed.



🚀 Installation \& Usage (For End Users)



Option 1: Direct Download (Recommended)



Go to the Releases Page (This link must be customized after uploading!).



Download the latest version of the File integrity Checker.exe file.



Double-click the EXE file to start the program.



Option 2: From Source Code



If you wish to run the source code yourself, you will need Python 3.x.



Clone the repository:



git clone \(https://github.com/SaturdayNetLab/FileIntegrityChecker.git))

cd Your-Repo-Name





Run the script:



python "File integrity Checker.py"





🛠️ Development \& Build Instructions



This project was built using Python and PyInstaller.



Prerequisites



Python 3.x



PyInstaller



Build Command



To recreate the standalone EXE file (with icon and without a console window), use this command:



python -m PyInstaller --onefile --windowed --icon="check\_icon-icons.com\_73639.ico" "File integrity Checker.py"







📜 License



This project is released under the MIT License.

