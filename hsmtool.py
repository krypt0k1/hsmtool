# hsm_tool.py - Main entry point for the HSM Tool
# This script serves as the main entry point for the HSM Tool, which is used to manage hardware security modules (HSMs).
# It imports the main function from the hsm_tool_script module and executes it.

from hsm_tool_script import main as hsm_tool_script_main

if __name__ == "__main__":
    hsm_tool_script_main()

