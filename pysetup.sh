#!/bin/bash
# This script sets up the Python environment for hey.py
# Ensure the script is run from the correct directory
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
echo $SCRIPT_DIR
cd "$SCRIPT_DIR" || exit 1

# Check if the virtual environment already exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
else
    echo "Virtual environment already exists."
fi

# Use the virtual environment's Python and pip directly
echo "Upgrading pip and installing requirements..."
venv/bin/python -m pip install --upgrade pip
venv/bin/pip install -r requirements.txt
# Check if script is executable
script="pytrace.py"
shtcut="pytrace"

echo "Proposed alias:"
bright="\033[97m"
resetc="\033[0m"
echo -e "${bright}alias $script='$SCRIPT_DIR/venv/bin/python3 $SCRIPT_DIR/$script'${resetc}"
#create shortcut in this folder
echo "./venv/bin/python3 $script \$@" > $shtcut
chmod +x "$script"
chmod +x "$shtcut"

originpybin=$(readlink -f ./venv/bin/python3)
echo -e "Scapy requires root. ${bright}This prompt grants permission to python3 binary (y/N):${resetc}"
read -r -p "" response
if [[ "$response" = "y" || "$response" = "Y" ]]; then
    echo "Setting setcap for $originpybin"
    sudo apt-get install -y libcap2-bin
    sudo setcap cap_net_raw+ep $originpybin
    echo "Setcap applied to $originpybin"
else
    echo "Setcap not applied. You may need to run pytrace.py with sudo"
fi