# 📦 Python PYC to PY Converter

A powerful Python reverse-engineering tool that reconstructs `.py` source code from `.pyc` files or disassembly dumps. It features a smart cross-version engine that automatically adapts to the target bytecode version.

---

### 🚀 Features

* **🔁 Convert .pyc → .py:** High-fidelity reconstruction.
* **🧠 Intelligent Source Reconstruction:** Goes beyond literal translation to rebuild high-level logic.
* **🔎 Cross-Version Disassembler:** Built-in engine to interpret opcodes across different Python versions.
* **🔧 Auto-Fixing:** Automatic syntax error correction and multi-pass post-processing.
* **🧩 Advanced Reconstruction:**
    * Decorators & Wrappers
    * Closures & `nonlocal` variables
    * Merged and optimized Imports
    * Complex `try/except/finally` blocks
    * Variadic arguments (`*args`, `**kwargs`)
* **⚙️ Version Management:** * Automatic Python version detection from `.pyc` headers.
    * Auto-relaunch with the correct Python interpreter if installed in PATH.

---

### 📂 Usage

python main.py <input.pyc> <output.py>



⚙️ OptionsOptionDescription--verbose / -vEnables verbose mode and saves a full disassembly dump.--forceBypasses Python version checks and forces translation.

🧠 How It WorksBytecode Parsing: 
	The tool reads marshal objects from .pyc files and reconstructs compatible code objects.Disassembly: A custom engine interprets opcodes and generates readable pseudo-source code.Reconstruction: The translator rebuilds scopes, variable names, logic flow, and control blocks.Post-Processing: Multiple passes fix indentation, deep nesting, and broken expressions.Note: Unreconstructible lines are marked with # TODO (decompile):

🧪 CompatibilitySupports .pyc files compiled with: Python 3.10 / 3.11 Python 3.12 / 3.13 / 3.14 (Latest Opcodes)

🛑 LimitationsComments (#) are stripped during compilation and cannot be recovered.
	Heavy obfuscation or bytecode manipulation may reduce reconstruction accuracy.
	Complex dynamic code may require minor manual cleanup.

💡 Example OutputPlaintext[OK] Source reconstructed → output.py

📜 LicenseFree to use for reverse engineering, analysis, research, and learning purposes.

🤝 ContributingContributions are welcome! Feel free to submit PRs to:Improve reconstruction accuracy.Support upcoming Python versions.Optimize post-processing logic.
